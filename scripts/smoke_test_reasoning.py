#!/usr/bin/env python3
"""Smoke test: POST /api/v1/reasoning with use_db=false and 1 cluster; confirm valid JSON and ReasoningResponse shape.

Run after starting the server: uvicorn app.main:app --reload
Optional: HELION_BASE_URL=http://localhost:8000 (default).
Requires: httpx (pip install httpx).
"""

import json
import os
import sys

import httpx

BASE_URL = os.environ.get("HELION_BASE_URL", "http://localhost:8000")
REASONING_URL = f"{BASE_URL}/api/v1/reasoning"

ONE_CLUSTER_PAYLOAD = {
    "use_db": False,
    "clusters": [
        {
            "vulnerability_id": "CVE-2024-SMOKE",
            "severity": "high",
            "repo": "smoke-repo",
            "file_path": "",
            "dependency": "",
            "cvss_score": 7.5,
            "description": "Smoke test vulnerability for reasoning endpoint.",
            "finding_ids": ["smoke-finding-1"],
            "affected_services_count": 1,
            "finding_count": 1,
        }
    ],
}


def _matches_reasoning_response(body: object) -> bool:
    """Check that body has ReasoningResponse shape: summary (str), cluster_notes (list of {vulnerability_id, priority, reasoning})."""
    if not isinstance(body, dict):
        return False
    if "summary" not in body or not isinstance(body["summary"], str):
        return False
    if "cluster_notes" not in body or not isinstance(body["cluster_notes"], list):
        return False
    for note in body["cluster_notes"]:
        if not isinstance(note, dict):
            return False
        if "vulnerability_id" not in note or "priority" not in note or "reasoning" not in note:
            return False
    return True


def main() -> None:
    print("Smoke test: POST /api/v1/reasoning (use_db=false, 1 cluster)")
    print(f"URL: {REASONING_URL}")
    try:
        response = httpx.post(
            REASONING_URL,
            json=ONE_CLUSTER_PAYLOAD,
            timeout=130.0,
        )
    except httpx.ConnectError as e:
        print("FAIL: Cannot connect to server. Start with: uvicorn app.main:app --reload")
        print(f"Error: {e}")
        sys.exit(1)

    if response.status_code != 200:
        print(f"FAIL: status {response.status_code}")
        print(response.text[:500])
        sys.exit(1)

    try:
        body = response.json()
    except json.JSONDecodeError as e:
        print(f"FAIL: response is not valid JSON: {e}")
        print(response.text[:500])
        sys.exit(1)

    if not _matches_reasoning_response(body):
        print("FAIL: response does not match ReasoningResponse shape (summary, cluster_notes with vulnerability_id, priority, reasoning)")
        print(f"Body keys: {list(body.keys()) if isinstance(body, dict) else 'not a dict'}")
        sys.exit(1)

    summary = body["summary"]
    cluster_notes = body["cluster_notes"]
    print("OK: valid JSON and matches ReasoningResponse shape")
    print(f"  summary length: {len(summary)}")
    print(f"  cluster_notes: {len(cluster_notes)}")
    if cluster_notes:
        first = cluster_notes[0]
        print(f"  first note: vulnerability_id={first.get('vulnerability_id')!r}, priority={first.get('priority')!r}")


if __name__ == "__main__":
    main()
