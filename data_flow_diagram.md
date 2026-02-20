# Helion data flow

High-level flow of vulnerability finding data from scanners into normalized and clustered representations.

## Upload flow

```mermaid
flowchart LR
  Client[Client]
  Upload[POST /api/v1/upload]
  Validate[Validate RawFinding]
  Normalize[Normalize to NormalizedFinding]
  DB[(Postgres findings)]
  Client -->|"JSON body or file"| Upload
  Upload --> Validate
  Validate --> Normalize
  Normalize --> DB
```

- **POST /api/v1/upload**: Accepts SAST/SCA findings as `application/json` (single object or array) or as `multipart/form-data` with a `.json` file. Validates each item as RawFinding, normalizes to NormalizedFinding, and persists rows to the `findings` table.

## Finding schemas flow

```mermaid
flowchart LR
  ScannerA[Scanner A]
  ScannerB[Scanner B]
  Raw[RawFinding]
  Norm[NormalizedFinding]
  Cluster[VulnerabilityCluster]
  ScannerA --> Raw
  ScannerB --> Raw
  Raw --> Norm
  Norm --> Cluster
```

- **RawFinding**: Scanner-agnostic ingestion; all fields optional so different scanners can be accepted. Optional `scanner_source` and `raw_payload` for traceability.
- **NormalizedFinding**: Unified internal representation; same seven fields with strict types and validation regardless of scanner.
- **VulnerabilityCluster**: One logical vulnerability (e.g. one CVE) grouped across multiple occurrences; canonical fields plus `finding_ids` referencing normalized findings.

## Shared field set

All three schemas use the same core fields: `vulnerability_id`, `severity`, `repo`, `file_path`, `dependency`, `cvss_score`, `description`.
