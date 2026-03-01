"""Upload endpoint: accept SAST/SCA JSON (body or file), validate, normalize, persist."""

import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.api.v1.auth import get_current_user
from app.core.database import get_db
from app.models import Finding, UploadJob
from app.schemas.auth import CurrentUser
from app.schemas.findings import RawFinding
from app.schemas.upload import UploadResponse
from app.services.normalize import deduplicate_finding_pairs, normalize_finding
from app.services.sarif_parser import sarif_to_rawfindings
from app.services.scanner_mappers import normalize_shape_to_rawfinding

router = APIRouter()

MAX_FINDINGS_PER_REQUEST = 10_000
MAX_UPLOAD_FILE_BYTES = 50 * 1024 * 1024  # 50 MB
ALLOWED_JSON_EXTENSIONS = frozenset({".json", ".sarif"})


def _is_upload_file(obj: object) -> bool:
    """True if obj is an uploaded file (UploadFile or file-like with filename and read)."""
    if isinstance(obj, UploadFile):
        return True
    return (
        hasattr(obj, "read")
        and callable(getattr(obj, "read", None))
        and hasattr(obj, "filename")
    )


def _is_sarif_root(data: dict) -> bool:
    """True if data is a SARIF root object (version, $schema, runs array)."""
    if not isinstance(data, dict) or "runs" not in data:
        return False
    if not data.get("version"):
        return False
    if not data.get("$schema"):
        return False
    runs = data.get("runs")
    return isinstance(runs, list)


def _is_osv_scanner_wrapper(data: dict) -> bool:
    """True if data looks like OSV-Scanner native JSON (top-level 'results' array)."""
    results = data.get("results")
    if not isinstance(results, list) or not results:
        return False
    first = results[0]
    return isinstance(first, dict) and "packages" in first


def _flatten_osv_scanner_results(data: dict) -> list[dict]:
    """
    Flatten OSV-Scanner { results: [ { source, packages: [ { package, vulnerabilities[] } ] } ] }
    to one dict per (source, package, vulnerability) for mapper consumption.
    """
    items: list[dict] = []
    for result in data.get("results") or []:
        if not isinstance(result, dict):
            continue
        source = result.get("source") or {}
        for pkg in result.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            package = pkg.get("package") or {}
            for vuln in pkg.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                flat: dict = {
                    "id": vuln.get("id"),
                    "aliases": vuln.get("aliases", []),
                    "package": package,
                    "source": source,
                }
                if vuln.get("summary") is not None:
                    flat["summary"] = vuln.get("summary")
                if vuln.get("details") is not None:
                    flat["details"] = vuln.get("details")
                if vuln.get("severity") is not None:
                    flat["severity"] = vuln.get("severity")
                if vuln.get("database_specific") is not None:
                    flat["database_specific"] = vuln.get("database_specific")
                items.append(flat)
    return items


def _parse_and_validate_findings(data: list | dict) -> list[RawFinding]:
    """Parse JSON structure into list of RawFinding; accept single object or array."""
    if isinstance(data, dict):
        if _is_sarif_root(data):
            items = sarif_to_rawfindings(data)
        elif _is_osv_scanner_wrapper(data):
            items = _flatten_osv_scanner_results(data)
        else:
            items = [data]
    elif isinstance(data, list):
        items = data
    else:
        raise HTTPException(
            status_code=422,
            detail="JSON body must be an array of findings or a single finding object.",
        )
    if len(items) > MAX_FINDINGS_PER_REQUEST:
        raise HTTPException(
            status_code=422,
            detail=f"At most {MAX_FINDINGS_PER_REQUEST} findings per request.",
        )
    findings: list[RawFinding] = []
    for i, raw_item in enumerate(items):
        if not isinstance(raw_item, dict):
            raise HTTPException(
                status_code=422,
                detail=f"Finding at index {i} must be an object.",
            )
        try:
            shaped = normalize_shape_to_rawfinding(raw_item)
            findings.append(RawFinding.model_validate(shaped))
        except ValidationError as e:
            raise HTTPException(status_code=422, detail=e.errors()) from e
    return findings


async def _get_findings_from_request(request: Request) -> list[RawFinding]:
    """Read request body or uploaded file and return validated list of RawFinding."""
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type == "application/json":
        try:
            body = await request.json()
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=422, detail=f"Invalid JSON: {e!s}") from e
        return _parse_and_validate_findings(body)
    if content_type == "multipart/form-data":
        form = await request.form()
        file = form.get("file")
        if file is None or not _is_upload_file(file):
            file = next(
                (v for v in form.values() if _is_upload_file(v)),
                None,
            )
        if file is None or not _is_upload_file(file):
            raise HTTPException(
                status_code=422,
                detail="Multipart request must include a 'file' field with a JSON or SARIF file.",
            )
        filename = getattr(file, "filename", None) or ""
        if not filename.lower().endswith((".json", ".sarif")):
            raise HTTPException(
                status_code=422,
                detail="Uploaded file must have a .json or .sarif extension.",
            )
        content = await file.read()
        if len(content) > MAX_UPLOAD_FILE_BYTES:
            raise HTTPException(
                status_code=422,
                detail=f"File size must not exceed {MAX_UPLOAD_FILE_BYTES // (1024*1024)} MB.",
            )
        try:
            data = json.loads(content.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise HTTPException(
                status_code=422, detail=f"Invalid JSON in file: {e!s}"
            ) from e
        return _parse_and_validate_findings(data)
    raise HTTPException(
        status_code=415,
        detail="Content-Type must be application/json or multipart/form-data.",
    )


def _upload_source_from_content_type(request: Request) -> str:
    """Return 'file' for multipart/form-data, 'api' for JSON."""
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    return "file" if content_type == "multipart/form-data" else "api"


@router.post("", response_model=UploadResponse, status_code=201)
async def upload_findings(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> UploadResponse:
    """
    Accept SAST/SCA findings as JSON and persist them. Requires authentication.

    - **JSON body**: Send `Content-Type: application/json` with either a single
      finding object or an array of finding objects.
    - **File upload**: Send `Content-Type: multipart/form-data` with a field
      named `file` containing a `.json` file with the same structure.

    Findings are validated with the raw finding schema, normalized, and stored
    in the database. Each upload creates an upload job; response includes
    upload_job_id for job-scoped clusters, reasoning, and export.
    """
    raw_list = await _get_findings_from_request(request)
    source = _upload_source_from_content_type(request)

    upload_job = UploadJob(
        user_id=current_user.id,
        status="processing",
        source=source,
    )
    db.add(upload_job)
    db.flush()

    if not raw_list:
        upload_job.status = "completed"
        db.commit()
        return UploadResponse(accepted=0, ids=[], upload_job_id=upload_job.id)

    pairs = [(raw, normalize_finding(raw)) for raw in raw_list]
    deduped = deduplicate_finding_pairs(pairs)

    ids: list[int] = []
    for raw, normalized in deduped:
        row = Finding(
            upload_job_id=upload_job.id,
            user_id=current_user.id,
            vulnerability_id=normalized.vulnerability_id,
            severity=normalized.severity,
            repo=normalized.repo,
            file_path=normalized.file_path,
            dependency=normalized.dependency,
            cvss_score=normalized.cvss_score,
            description=normalized.description,
            scanner_source=raw.scanner_source,
            raw_payload=raw.raw_payload,
        )
        db.add(row)
        db.flush()
        ids.append(row.id)
    upload_job.status = "completed"
    db.commit()
    return UploadResponse(accepted=len(ids), ids=ids, upload_job_id=upload_job.id)
