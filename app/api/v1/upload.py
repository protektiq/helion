"""Upload endpoint: accept SAST/SCA JSON (body or file), validate, normalize, persist."""

import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Finding
from app.schemas.findings import RawFinding
from app.schemas.upload import UploadResponse
from app.services.normalize import deduplicate_finding_pairs, normalize_finding
from app.services.scanner_mappers import normalize_shape_to_rawfinding

router = APIRouter()

MAX_FINDINGS_PER_REQUEST = 10_000
MAX_UPLOAD_FILE_BYTES = 50 * 1024 * 1024  # 50 MB
ALLOWED_JSON_EXTENSIONS = frozenset({".json"})


def _is_upload_file(obj: object) -> bool:
    """True if obj is an uploaded file (UploadFile or file-like with filename and read)."""
    if isinstance(obj, UploadFile):
        return True
    return (
        hasattr(obj, "read")
        and callable(getattr(obj, "read", None))
        and hasattr(obj, "filename")
    )


def _parse_and_validate_findings(data: list | dict) -> list[RawFinding]:
    """Parse JSON structure into list of RawFinding; accept single object or array."""
    if isinstance(data, dict):
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
            # Some clients send the file under another name; use first file-like part.
            file = next(
                (v for v in form.values() if _is_upload_file(v)),
                None,
            )
        if file is None or not _is_upload_file(file):
            raise HTTPException(
                status_code=422,
                detail="Multipart request must include a 'file' field with a JSON file.",
            )
        filename = getattr(file, "filename", None) or ""
        if not filename.lower().endswith(".json"):
            raise HTTPException(
                status_code=422,
                detail="Uploaded file must have a .json extension.",
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


@router.post("", response_model=UploadResponse, status_code=201)
async def upload_findings(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> UploadResponse:
    """
    Accept SAST/SCA findings as JSON and persist them.

    - **JSON body**: Send `Content-Type: application/json` with either a single
      finding object or an array of finding objects.
    - **File upload**: Send `Content-Type: multipart/form-data` with a field
      named `file` containing a `.json` file with the same structure.

    Findings are validated with the raw finding schema, normalized, and stored
    in the database. Returns the count of accepted findings and their IDs.
    """
    raw_list = await _get_findings_from_request(request)
    if not raw_list:
        return UploadResponse(accepted=0, ids=[])

    pairs = [(raw, normalize_finding(raw)) for raw in raw_list]
    deduped = deduplicate_finding_pairs(pairs)

    ids: list[int] = []
    for raw, normalized in deduped:
        row = Finding(
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
    db.commit()
    return UploadResponse(accepted=len(ids), ids=ids)
