"""Helpers to load findings scoped by upload job and user."""

from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from app.models import Finding, UploadJob
from app.schemas.findings import (
    RULES_DISAGREEMENT_LIMIT,
    TOP_NOISY_RULES_LIMIT,
    RuleCount,
    RuleSeverityDisagreement,
    RuleSummary,
)


def get_user_upload_job_count(db: Session, user_id: int) -> int:
    """Return the number of upload jobs for the given user."""
    return (
        db.query(UploadJob)
        .filter(UploadJob.user_id == user_id)
        .count()
    )


def get_findings_for_user_job(
    db: Session,
    user_id: int,
    job_id: int | None = None,
) -> list:
    """
    Return findings for the current user, optionally scoped to one upload job.

    - If job_id is set: return findings for that job (and enforce user_id).
    - If job_id is None: return findings for the user's latest job (by created_at).
    - If the user has no jobs or the specified job is not theirs, return empty list.
    """
    if job_id is not None:
        return (
            db.query(Finding)
            .filter(Finding.upload_job_id == job_id, Finding.user_id == user_id)
            .all()
        )
    # Latest job for user
    latest = (
        db.query(UploadJob)
        .filter(UploadJob.user_id == user_id)
        .order_by(UploadJob.created_at.desc())
        .limit(1)
        .first()
    )
    if latest is None:
        return []
    return (
        db.query(Finding)
        .filter(Finding.upload_job_id == latest.id, Finding.user_id == user_id)
        .all()
    )


def _is_semgrep_finding(finding: Any) -> bool:
    """True if the finding is from Semgrep (scanner_source set by map_semgrep_to_raw)."""
    source = getattr(finding, "scanner_source", None)
    return isinstance(source, str) and source.strip().lower() == "semgrep"


def summarize_rules(findings: list[Finding]) -> RuleSummary:
    """
    Build rule-level analytics from findings for workshop credibility (SAST triage).

    Filters to Semgrep findings only. Returns top noisy rules (by finding count) and
    rules with severity disagreement (same rule, multiple severities). List lengths
    are capped to keep the response bounded.

    Input validation: findings must be a list; each element must have vulnerability_id,
    scanner_source, and severity (Finding model or duck-typed equivalent).
    """
    if not isinstance(findings, list):
        return RuleSummary(top_noisy_rules=[], rules_with_severity_disagreement=[])

    semgrep_findings = [
        f
        for f in findings
        if _is_semgrep_finding(f)
        and getattr(f, "vulnerability_id", None)
        and isinstance(getattr(f, "vulnerability_id", None), str)
        and (getattr(f, "vulnerability_id", "") or "").strip()
    ]
    if not semgrep_findings:
        return RuleSummary(top_noisy_rules=[], rules_with_severity_disagreement=[])

    # Top noisy rules: group by rule_id (vulnerability_id), count, sort desc, cap
    rule_counts: dict[str, int] = defaultdict(int)
    for f in semgrep_findings:
        rule_id = (getattr(f, "vulnerability_id", "") or "").strip()
        if rule_id:
            rule_counts[rule_id] += 1
    top_noisy = sorted(
        [RuleCount(rule_id=rid, count=c) for rid, c in rule_counts.items()],
        key=lambda x: (-x.count, x.rule_id),
    )[:TOP_NOISY_RULES_LIMIT]

    # Severity disagreement: (rule_id, severity) -> count; then rule_id -> {severity: count}
    rule_severities: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in semgrep_findings:
        rule_id = (getattr(f, "vulnerability_id", "") or "").strip()
        sev = getattr(f, "severity", None)
        if not rule_id:
            continue
        sev_str = (str(sev).strip().lower()) if sev is not None else "unknown"
        rule_severities[rule_id][sev_str] += 1
    disagreement = [
        RuleSeverityDisagreement(rule_id=rid, severity_counts=dict(sev_counts))
        for rid, sev_counts in rule_severities.items()
        if len(sev_counts) > 1
    ]
    # Stable order: by rule_id, then cap
    disagreement.sort(key=lambda x: x.rule_id)
    disagreement = disagreement[:RULES_DISAGREEMENT_LIMIT]

    return RuleSummary(
        top_noisy_rules=top_noisy,
        rules_with_severity_disagreement=disagreement,
    )
