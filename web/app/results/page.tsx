"use client";

import { useState, useCallback, useEffect } from "react";
import Link from "next/link";

const DEFAULT_API_URL = "http://localhost:8000";

const SEVERITY_ORDER: readonly string[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

type ClustersResponse = {
  metrics: {
    raw_finding_count: number;
    cluster_count: number;
    compression_ratio: number;
  };
  clusters: Array<{ severity: string }>;
};

function isValidClustersResponse(
  data: unknown
): data is ClustersResponse {
  if (data === null || typeof data !== "object") return false;
  const o = data as Record<string, unknown>;
  if (!o.metrics || typeof o.metrics !== "object") return false;
  const m = o.metrics as Record<string, unknown>;
  if (
    typeof m.raw_finding_count !== "number" ||
    typeof m.cluster_count !== "number" ||
    typeof m.compression_ratio !== "number"
  ) {
    return false;
  }
  if (!Array.isArray(o.clusters)) return false;
  return true;
}

type JiraExportResponse = {
  epics?: Record<string, string>;
  issues?: Array<{ title: string; key: string; tier: string }>;
  errors?: string[];
};

function getApiBaseUrl(): string {
  if (typeof process.env.NEXT_PUBLIC_API_URL !== "string") {
    return DEFAULT_API_URL;
  }
  const url = process.env.NEXT_PUBLIC_API_URL.trim();
  return url.length > 0 ? url.replace(/\/+$/, "") : DEFAULT_API_URL;
}

function severityBreakdown(clusters: Array<{ severity: string }>): Record<string, number> {
  const counts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const c of clusters) {
    const s = String(c.severity ?? "").toLowerCase().trim();
    if (s in counts) {
      counts[s] += 1;
    }
  }
  return counts;
}

function capitalizeSeverity(s: string): string {
  if (!s) return s;
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}

export default function ResultsSummaryPage() {
  const [summary, setSummary] = useState<ClustersResponse | null>(null);
  const [loadStatus, setLoadStatus] = useState<"idle" | "loading" | "success" | "error">("idle");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [exportStatus, setExportStatus] = useState<"idle" | "exporting" | "success" | "error">("idle");
  const [exportMessage, setExportMessage] = useState<string | null>(null);

  const fetchSummary = useCallback(async () => {
    const baseUrl = getApiBaseUrl();
    setLoadStatus("loading");
    setLoadError(null);
    try {
      const res = await fetch(`${baseUrl}/api/v1/clusters`);
      if (!res.ok) {
        const contentType = res.headers.get("content-type") ?? "";
        let detail = res.statusText;
        if (contentType.includes("application/json")) {
          try {
            const body = (await res.json()) as { detail?: string | string[] };
            if (Array.isArray(body.detail)) {
              detail = body.detail.map((d) => String(d)).join("; ");
            } else if (typeof body.detail === "string") {
              detail = body.detail;
            }
          } catch {
            // keep detail as statusText
          }
        }
        setLoadError(detail);
        setLoadStatus("error");
        return;
      }
      const data: unknown = await res.json();
      if (!isValidClustersResponse(data)) {
        setLoadError("Invalid response shape from API.");
        setLoadStatus("error");
        return;
      }
      setSummary(data);
      setLoadStatus("success");
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Network or request failed.";
      setLoadError(message);
      setLoadStatus("error");
    }
  }, []);

  useEffect(() => {
    fetchSummary();
  }, [fetchSummary]);

  const handleExportToJira = useCallback(async () => {
    const baseUrl = getApiBaseUrl();
    setExportStatus("exporting");
    setExportMessage(null);
    try {
      const res = await fetch(`${baseUrl}/api/v1/jira/export`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ use_db: true, use_reasoning: false }),
      });
      const data: unknown = await res.json().catch(() => ({}));
      const jira = data as JiraExportResponse;
      const errors = Array.isArray(jira.errors) ? jira.errors : [];

      if (!res.ok) {
        let detail = res.statusText;
        if (data !== null && typeof data === "object" && "detail" in data) {
          const d = (data as { detail?: string | string[] }).detail;
          if (typeof d === "string") detail = d;
          else if (Array.isArray(d)) detail = d.map((x) => String(x)).join("; ");
        }
        setExportMessage(errors.length > 0 ? [...errors, detail].join(" ") : detail);
        setExportStatus("error");
        return;
      }

      const issueCount = Array.isArray(jira.issues) ? jira.issues.length : 0;
      const epicCount =
        jira.epics && typeof jira.epics === "object"
          ? Object.keys(jira.epics).length
          : 0;
      let msg = `Exported ${issueCount} issue(s) under ${epicCount} epic(s).`;
      if (errors.length > 0) {
        msg += " " + errors.join(" ");
      }
      setExportMessage(msg);
      setExportStatus("success");
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Network or request failed.";
      setExportMessage(message);
      setExportStatus("error");
    }
  }, []);

  const breakdown =
    summary !== null ? severityBreakdown(summary.clusters) : null;

  return (
    <main style={{ padding: "2rem", maxWidth: "40rem", margin: "0 auto" }}>
      <h1 style={{ fontSize: "1.25rem", marginBottom: "1rem" }}>
        Results summary
      </h1>

      <nav style={{ marginBottom: "1.5rem" }}>
        <Link
          href="/"
          style={{ color: "#2563eb", textDecoration: "underline" }}
          aria-label="Go to upload page"
        >
          Upload
        </Link>
      </nav>

      {loadStatus === "loading" && (
        <p role="status" aria-live="polite">
          Loading summary…
        </p>
      )}

      {loadStatus === "error" && loadError !== null && (
        <div
          role="alert"
          style={{ marginBottom: "1rem", color: "#b91c1c" }}
        >
          <p>{loadError}</p>
          <button
            type="button"
            onClick={fetchSummary}
            aria-label="Retry loading summary"
          >
            Retry
          </button>
        </div>
      )}

      {loadStatus === "success" && summary !== null && (
        <>
          <table
            style={{
              width: "100%",
              borderCollapse: "collapse",
              marginBottom: "1.5rem",
            }}
            aria-label="Results summary"
          >
            <caption style={{ textAlign: "left", marginBottom: "0.5rem" }}>
              Summary of findings and clusters
            </caption>
            <thead>
              <tr>
                <th
                  scope="col"
                  style={{
                    textAlign: "left",
                    padding: "0.5rem 0.75rem",
                    borderBottom: "1px solid #e5e7eb",
                  }}
                >
                  Metric
                </th>
                <th
                  scope="col"
                  style={{
                    textAlign: "right",
                    padding: "0.5rem 0.75rem",
                    borderBottom: "1px solid #e5e7eb",
                  }}
                >
                  Count
                </th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td
                  style={{
                    padding: "0.5rem 0.75rem",
                    borderBottom: "1px solid #e5e7eb",
                  }}
                >
                  Raw findings count
                </td>
                <td
                  style={{
                    padding: "0.5rem 0.75rem",
                    borderBottom: "1px solid #e5e7eb",
                    textAlign: "right",
                  }}
                >
                  {summary.metrics.raw_finding_count}
                </td>
              </tr>
              <tr>
                <td
                  style={{
                    padding: "0.5rem 0.75rem",
                    borderBottom: "1px solid #e5e7eb",
                  }}
                >
                  Cluster count
                </td>
                <td
                  style={{
                    padding: "0.5rem 0.75rem",
                    borderBottom: "1px solid #e5e7eb",
                    textAlign: "right",
                  }}
                >
                  {summary.metrics.cluster_count}
                </td>
              </tr>
              {breakdown !== null &&
                SEVERITY_ORDER.map((sev) => (
                  <tr key={sev}>
                    <td
                      style={{
                        padding: "0.5rem 0.75rem",
                        borderBottom: "1px solid #e5e7eb",
                      }}
                    >
                      Risk tier ({capitalizeSeverity(sev)})
                    </td>
                    <td
                      style={{
                        padding: "0.5rem 0.75rem",
                        borderBottom: "1px solid #e5e7eb",
                        textAlign: "right",
                      }}
                    >
                      {breakdown[sev]}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>

          <div style={{ marginBottom: "1rem" }}>
            <button
              type="button"
              onClick={handleExportToJira}
              disabled={exportStatus === "exporting"}
              aria-busy={exportStatus === "exporting"}
              aria-label={
                exportStatus === "exporting"
                  ? "Exporting to Jira"
                  : "Export to Jira"
              }
            >
              {exportStatus === "exporting" ? "Exporting…" : "Export to Jira"}
            </button>
          </div>

          <div
            role="status"
            aria-live="polite"
            style={{ minHeight: "1.5em" }}
          >
            {exportStatus === "success" && exportMessage !== null && (
              <p style={{ color: "#166534" }}>{exportMessage}</p>
            )}
            {exportStatus === "error" && exportMessage !== null && (
              <p style={{ color: "#b91c1c" }}>{exportMessage}</p>
            )}
          </div>
        </>
      )}

      {loadStatus === "success" && summary === null && (
        <p role="status">No summary data.</p>
      )}
    </main>
  );
}
