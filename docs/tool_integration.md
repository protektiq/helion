# Tool integration guide

This document provides checklists for integrating a new open-source (or proprietary) security tool into Helion. The core pipeline is tool-agnostic after shape mapping; each integration is one or both of:

- **Mapper/parser into RawFinding** — so the tool’s JSON becomes findings that flow through normalize → dedupe → persist → cluster.
- **Enrichment provider** — so the tool’s data attaches evidence to clusters used by reasoning and tickets.

See [data_flow_diagram.md](../data_flow_diagram.md) (section **Tool integration**) for the high-level contracts and file locations.

---

## Adding a new scanner (mapper into RawFinding)

Goal: accept the tool’s JSON output so that each finding is mapped to RawFinding, then normalized, deduped, persisted, and clustered. The upload UI accepts any `.json` file; the backend runs each array element through the mapper pipeline. If no scanner heuristic matches, **generic aliases** are applied (see `GENERIC_ALIASES` in `scanner_mappers.py`), so a tool that already uses similar field names may work without a custom mapper.

### Checklist

1. **Add a heuristic** in [app/services/scanner_mappers.py](app/services/scanner_mappers.py):
   - Implement `_is_<tool>_like(obj: dict) -> bool` (e.g. check for tool-specific top-level keys, `@type`, or a known structure).
   - Keep the check cheap and specific enough to avoid false positives with other scanners.

2. **Add a mapper function** in the same file:
   - Implement `map_<tool>_to_raw(obj: dict) -> dict`.
   - Map the tool’s fields to the keys expected by RawFinding: `vulnerability_id`, `severity`, `repo`, `file_path`, `dependency`, `cvss_score`, `description`, `scanner_source`, `raw_payload`.
   - Preserve the original object in `raw_payload`.
   - Set `scanner_source` to a stable identifier (e.g. `"mytool"`).
   - Use helpers such as `_str_or_none()` and `_merge_rawfinding_shape()` for consistency with existing mappers.

3. **Register the mapper** in `normalize_shape_to_rawfinding()`:
   - Add a branch **before** the generic fallback:  
     `if _is_<tool>_like(obj): return map_<tool>_to_raw(obj)`.
   - Order matters: more specific scanners should be checked before generic aliases.

4. **Verify downstream:** No other code changes are required. The upload flow in [app/api/v1/upload.py](app/api/v1/upload.py) already calls `normalize_shape_to_rawfinding()` then `RawFinding.model_validate()`; normalize, dedupe, persist, and clustering all use the unified shapes.

### Reference

- Existing mappers: Trivy (`map_trivy_to_raw`), Snyk (`map_snyk_to_raw`), Semgrep (`map_semgrep_to_raw`) and `apply_generic_aliases` in [app/services/scanner_mappers.py](app/services/scanner_mappers.py).
- RawFinding schema: [app/schemas/findings.py](app/schemas/findings.py). All fields are optional for ingestion; the normalizer fills defaults and standardizes severity/CVE/GHSA.

---

## Adding a new enrichment provider

Goal: attach evidence (and optionally structured data) from an external source to each cluster, so that reasoning and ticket generation can use it. Enrichment runs when the exploitability/reasoning agent runs (e.g. POST /api/v1/reasoning or POST /api/v1/exploitability); results are stored in the `cluster_enrichments` table (JSONB).

### Checklist

1. **Add a client module** under [app/services/enrichment/](app/services/enrichment/):
   - Create e.g. `client_<source>.py` with an async function that takes the cluster (or `vulnerability_id` / `dependency`) and app `Settings`, and returns the tool’s data (or `None` on failure).
   - Use existing timeouts and error handling patterns from [client_kev.py](app/services/enrichment/client_kev.py), [client_epss.py](app/services/enrichment/client_epss.py), or [client_osv.py](app/services/enrichment/client_osv.py).

2. **Wire into the orchestrator** in [app/services/enrichment/enrich_cluster.py](app/services/enrichment/enrich_cluster.py):
   - Add a feature flag (e.g. `ENRICHMENT_<SOURCE>_ENABLED`) in [app/core/config.py](app/core/config.py) if not already present.
   - In `enrich_cluster()`, when the flag is enabled, call the new client and append short evidence strings to the `evidence` list (e.g. `"<Source> listed"` or `"<Source> score 0.12"`).
   - If the tool returns structured data (e.g. a list of advisories), set or extend fields on the payload as needed.

3. **Extend the payload schema if needed** in [app/services/enrichment/schemas.py](app/services/enrichment/schemas.py):
   - If the provider adds new structured fields, add them to `ClusterEnrichmentPayload` with bounded list/string lengths (e.g. `max_length=50` for lists) for safe storage and validation.

4. **Document configuration** in `.env.example`:
   - Add the new env vars (e.g. `ENRICHMENT_<SOURCE>_ENABLED`, and any URLs or API keys) with a short note for operators.

### Reference

- KEV/EPSS/OSV usage in [enrich_cluster.py](app/services/enrichment/enrich_cluster.py) (lines 82–107).
- Payload and evidence shape: [app/services/enrichment/schemas.py](app/services/enrichment/schemas.py).
- Persistence: callers (e.g. [app/services/agent/nodes.py](app/services/agent/nodes.py)) call `save_cluster_enrichment()` with the dict returned from `enrich_cluster()` to store results in `cluster_enrichments`.
