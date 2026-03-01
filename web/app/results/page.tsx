"use client";

import { useState, useCallback, useEffect, useMemo } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { createApiClient, getErrorMessage, getValidationDetail } from "@/lib/apiClient";
import { getSelectedJobId, setSelectedJobId } from "@/lib/jobStorage";
import ErrorAlert from "@/app/components/ErrorAlert";
import type {
  ClustersResponse,
  JiraExportResponse,
  UploadJobListItem,
  ValidationError,
  VulnerabilityCluster,
} from "@/lib/types";

const SEVERITY_ORDER: readonly string[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

const MAX_SEARCH_LENGTH = 200;

const TIER_LABELS = ["Tier 1", "Tier 2", "Tier 3"] as const;
type TierLabel = (typeof TIER_LABELS)[number];

function severityToTierLabel(severity: string): TierLabel {
  const s = String(severity ?? "").toLowerCase().trim();
  if (s === "critical") return "Tier 1";
  if (s === "high") return "Tier 2";
  return "Tier 3";
}

function severityBreakdown(clusters: VulnerabilityCluster[]): Record<string, number> {
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

const JOB_ID_PARAM = "job_id";

export default function ResultsSummaryPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const jobIdParam = searchParams.get(JOB_ID_PARAM);
  const jobIdFromUrl =
    jobIdParam !== null && jobIdParam !== ""
      ? parseInt(jobIdParam, 10)
      : undefined;
  const urlJobIdValid =
    jobIdFromUrl !== undefined && !Number.isNaN(jobIdFromUrl);

  const [summary, setSummary] = useState<ClustersResponse | null>(null);
  const [jobs, setJobs] = useState<UploadJobListItem[]>([]);
  const [loadStatus, setLoadStatus] = useState<"idle" | "loading" | "success" | "error">("idle");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loadErrorDetail, setLoadErrorDetail] = useState<ValidationError[] | null>(null);
  const [exportStatus, setExportStatus] = useState<"idle" | "exporting" | "success" | "error">("idle");
  const [exportMessage, setExportMessage] = useState<string | null>(null);
  const [exportDetail, setExportDetail] = useState<ValidationError[] | null>(null);
  const [manualTierOverride, setManualTierOverride] = useState(false);
  const [tierOverrides, setTierOverrides] = useState<Record<string, string>>({});
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState("");

  const fetchSummary = useCallback(
    async (jobId?: number | null) => {
      setLoadStatus("loading");
      setLoadError(null);
      setLoadErrorDetail(null);
      try {
        const client = createApiClient();
        const data = await client.getClusters(jobId);
        setSummary(data);
        setLoadStatus("success");
      } catch (err) {
        setLoadError(getErrorMessage(err));
        setLoadErrorDetail(getValidationDetail(err));
        setLoadStatus("error");
      }
    },
    []
  );

  const fetchJobs = useCallback(async () => {
    try {
      const client = createApiClient();
      const res = await client.listUploadJobs();
      setJobs(res.jobs ?? []);
    } catch {
      setJobs([]);
    }
  }, []);

  useEffect(() => {
    fetchJobs();
  }, [fetchJobs]);

  const jobIds = useMemo(() => new Set(jobs.map((j) => j.id)), [jobs]);
  const effectiveJobId = useMemo(() => {
    if (urlJobIdValid && jobIds.has(jobIdFromUrl!)) return jobIdFromUrl!;
    if (jobs.length > 1) {
      const stored = getSelectedJobId();
      if (stored !== null && jobIds.has(stored)) return stored;
      return jobs[0].id;
    }
    if (jobs.length === 1) return jobs[0].id;
    return undefined;
  }, [urlJobIdValid, jobIdFromUrl, jobIds, jobs]);

  useEffect(() => {
    if (effectiveJobId === undefined) {
      fetchSummary(undefined);
      return;
    }
    setSelectedJobId(effectiveJobId);
    fetchSummary(effectiveJobId);
  }, [effectiveJobId, fetchSummary]);

  useEffect(() => {
    if (jobs.length > 1 && effectiveJobId !== undefined && (!urlJobIdValid || jobIdFromUrl !== effectiveJobId)) {
      setSelectedJobId(effectiveJobId);
      router.replace(`/results?${JOB_ID_PARAM}=${effectiveJobId}`);
    }
  }, [jobs.length, effectiveJobId, urlJobIdValid, jobIdFromUrl, router]);

  const handleJobSelect = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      const val = e.target.value;
      const id = parseInt(val, 10);
      if (Number.isNaN(id)) return;
      setSelectedJobId(id);
      router.replace(`/results?${JOB_ID_PARAM}=${id}`);
    },
    [router]
  );

  const handleManualOverrideChange = useCallback(() => {
    setManualTierOverride((prev) => {
      const next = !prev;
      if (next && summary?.clusters?.length) {
        const initial: Record<string, string> = {};
        for (const c of summary.clusters) {
          initial[c.vulnerability_id] = severityToTierLabel(c.severity);
        }
        setTierOverrides(initial);
      }
      return next;
    });
  }, [summary?.clusters]);

  const handleTierChange = useCallback((vulnerabilityId: string, tier: string) => {
    if (tier !== "Tier 1" && tier !== "Tier 2" && tier !== "Tier 3") return;
    setTierOverrides((prev) => ({ ...prev, [vulnerabilityId]: tier }));
  }, []);

  const handleExportToJira = useCallback(async () => {
    setExportStatus("exporting");
    setExportMessage(null);
    setExportDetail(null);
    const body = {
      clusters: [] as VulnerabilityCluster[],
      use_db: true,
      use_reasoning: false,
      ...(effectiveJobId != null ? { job_id: effectiveJobId } : {}),
      ...(manualTierOverride && Object.keys(tierOverrides).length > 0
        ? { tier_overrides: tierOverrides }
        : {}),
    };
    try {
      const client = createApiClient();
      const jira: JiraExportResponse = await client.postJiraExport(body);
      const errors = Array.isArray(jira.errors) ? jira.errors : [];
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
      setExportMessage(getErrorMessage(err));
      setExportDetail(getValidationDetail(err));
      setExportStatus("error");
    }
  }, [effectiveJobId, manualTierOverride, tierOverrides]);

  const breakdown =
    summary !== null ? severityBreakdown(summary.clusters) : null;

  const filteredClusters = useMemo(() => {
    if (summary === null || !summary.clusters.length) return [];
    let list = summary.clusters;
    const sev = severityFilter.trim().toLowerCase();
    if (sev && SEVERITY_ORDER.includes(sev)) {
      list = list.filter(
        (c) => String(c.severity ?? "").toLowerCase().trim() === sev
      );
    }
    const query = searchQuery.trim().slice(0, MAX_SEARCH_LENGTH).toLowerCase();
    if (!query) return list;
    return list.filter((c) => {
      const vid = String(c.vulnerability_id ?? "").toLowerCase();
      const dep = String(c.dependency ?? "").toLowerCase();
      const repo = String(c.repo ?? "").toLowerCase();
      return vid.includes(query) || dep.includes(query) || repo.includes(query);
    });
  }, [summary, severityFilter, searchQuery]);

  const handleRefresh = useCallback(() => {
    fetchSummary(effectiveJobId);
  }, [effectiveJobId, fetchSummary]);

  const handleSeverityFilterChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      setSeverityFilter(e.target.value);
    },
    []
  );

  const handleSearchChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setSearchQuery(e.target.value);
    },
    []
  );

  return (
    <main style={{ padding: "2rem", maxWidth: "40rem", margin: "0 auto" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "1rem", marginBottom: "1rem", flexWrap: "wrap" }}>
        <h1 style={{ fontSize: "1.25rem", margin: 0 }}>
          Results summary
        </h1>
        {jobs.length > 0 && (
          <label style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <span style={{ whiteSpace: "nowrap" }}>Upload job</span>
            <select
              value={effectiveJobId ?? ""}
              onChange={handleJobSelect}
              aria-label="Select upload job to view clusters"
              style={{ minWidth: "12rem" }}
            >
              {jobs.map((j) => (
                <option key={j.id} value={j.id}>
                  Job {j.id} ({j.finding_count} findings, {j.created_at.slice(0, 10)})
                </option>
              ))}
            </select>
          </label>
        )}
        <button
          type="button"
          onClick={handleRefresh}
          disabled={loadStatus === "loading"}
          aria-busy={loadStatus === "loading"}
          aria-label={loadStatus === "loading" ? "Refreshing" : "Refresh clusters and metrics"}
        >
          {loadStatus === "loading" ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      <nav style={{ marginBottom: "1.5rem" }}>
        <Link
          href="/upload"
          style={{ color: "#2563eb", textDecoration: "underline" }}
          aria-label="Go to upload page"
        >
          Upload
        </Link>
        {" · "}
        <Link
          href="/tickets"
          style={{ color: "#2563eb", textDecoration: "underline" }}
          aria-label="Go to Tickets"
        >
          Tickets
        </Link>
        {" · "}
        <Link
          href="/jira"
          style={{ color: "#2563eb", textDecoration: "underline" }}
          aria-label="Go to Jira Export"
        >
          Jira Export
        </Link>
      </nav>

      {loadStatus === "loading" && (
        <p role="status" aria-live="polite">
          Loading summary…
        </p>
      )}

      {loadStatus === "error" && loadError !== null && (
        <ErrorAlert
          message={loadError}
          detail={loadErrorDetail}
          onRetry={fetchSummary}
          retryLabel="Retry loading summary"
        />
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
              <tr>
                <td
                  style={{
                    padding: "0.5rem 0.75rem",
                    borderBottom: "1px solid #e5e7eb",
                  }}
                >
                  Compression ratio
                </td>
                <td
                  style={{
                    padding: "0.5rem 0.75rem",
                    borderBottom: "1px solid #e5e7eb",
                    textAlign: "right",
                  }}
                >
                  {typeof summary.metrics.compression_ratio === "number"
                    ? summary.metrics.compression_ratio.toFixed(2)
                    : summary.metrics.compression_ratio}
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

          {summary.rule_summary != null &&
            (summary.rule_summary.top_noisy_rules.length > 0 ||
              summary.rule_summary.rules_with_severity_disagreement.length > 0) && (
            <section
              style={{ marginBottom: "1.5rem" }}
              aria-label="Top rules by volume (Semgrep SAST)"
            >
              <h2 style={{ fontSize: "1rem", marginBottom: "0.75rem" }}>
                Top rules by volume
              </h2>
              {summary.rule_summary.top_noisy_rules.length > 0 && (
                <div
                  style={{
                    border: "1px solid #e5e7eb",
                    borderRadius: "4px",
                    overflow: "auto",
                    maxHeight: "16rem",
                    marginBottom: "0.75rem",
                  }}
                  role="region"
                  aria-label="Top noisy rules table"
                >
                  <table
                    style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.875rem" }}
                    aria-label="Top noisy rules: rule ID and finding count"
                  >
                    <thead>
                      <tr style={{ borderBottom: "1px solid #e5e7eb", backgroundColor: "#f9fafb" }}>
                        <th scope="col" style={{ textAlign: "left", padding: "0.5rem 0.75rem" }}>
                          Rule ID
                        </th>
                        <th scope="col" style={{ textAlign: "right", padding: "0.5rem 0.75rem" }}>
                          Count
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {summary.rule_summary.top_noisy_rules.map((r) => (
                        <tr key={r.rule_id} style={{ borderBottom: "1px solid #e5e7eb" }}>
                          <td style={{ padding: "0.5rem 0.75rem", wordBreak: "break-all" }} title={r.rule_id}>
                            {r.rule_id}
                          </td>
                          <td style={{ padding: "0.5rem 0.75rem", textAlign: "right" }}>
                            {r.count}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {summary.rule_summary.rules_with_severity_disagreement.length > 0 && (
                <div style={{ fontSize: "0.875rem" }}>
                  <h3 style={{ fontSize: "0.9375rem", marginBottom: "0.5rem" }}>
                    Rules with severity disagreement
                  </h3>
                  <div
                    style={{
                      border: "1px solid #e5e7eb",
                      borderRadius: "4px",
                      overflow: "auto",
                      maxHeight: "12rem",
                    }}
                    role="region"
                    aria-label="Rules with severity disagreement"
                  >
                    <table
                      style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.875rem" }}
                      aria-label="Rules with multiple severities"
                    >
                      <thead>
                        <tr style={{ borderBottom: "1px solid #e5e7eb", backgroundColor: "#f9fafb" }}>
                          <th scope="col" style={{ textAlign: "left", padding: "0.5rem 0.75rem" }}>
                            Rule ID
                          </th>
                          <th scope="col" style={{ textAlign: "left", padding: "0.5rem 0.75rem" }}>
                            Severity counts
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {summary.rule_summary.rules_with_severity_disagreement.map((r) => (
                          <tr key={r.rule_id} style={{ borderBottom: "1px solid #e5e7eb" }}>
                            <td style={{ padding: "0.5rem 0.75rem", wordBreak: "break-all" }} title={r.rule_id}>
                              {r.rule_id}
                            </td>
                            <td style={{ padding: "0.5rem 0.75rem" }}>
                              {Object.entries(r.severity_counts)
                                .map(([sev, c]) => `${sev}: ${c}`)
                                .join(", ")}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </section>
          )}

          <section style={{ marginBottom: "1.5rem" }} aria-label="Cluster list and filters">
            <h2 style={{ fontSize: "1rem", marginBottom: "0.75rem" }}>Clusters</h2>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem 1rem", marginBottom: "0.75rem", alignItems: "center" }}>
              <label style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <span style={{ whiteSpace: "nowrap" }}>Severity</span>
                <select
                  value={severityFilter}
                  onChange={handleSeverityFilterChange}
                  aria-label="Filter clusters by severity"
                  style={{ minWidth: "8rem" }}
                >
                  <option value="">All</option>
                  {SEVERITY_ORDER.map((s) => (
                    <option key={s} value={s}>
                      {capitalizeSeverity(s)}
                    </option>
                  ))}
                </select>
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", flex: "1 1 12rem", minWidth: 0 }}>
                <span style={{ whiteSpace: "nowrap" }}>Search</span>
                <input
                  type="search"
                  value={searchQuery}
                  onChange={handleSearchChange}
                  placeholder="vulnerability_id, dependency, repo…"
                  aria-label="Search clusters by vulnerability ID, dependency, or repo"
                  maxLength={MAX_SEARCH_LENGTH}
                  style={{ flex: 1, minWidth: 0 }}
                />
              </label>
            </div>
            <div
              style={{
                border: "1px solid #e5e7eb",
                borderRadius: "4px",
                overflow: "auto",
                maxHeight: "24rem",
              }}
              role="region"
              aria-label="Cluster list"
            >
              <table
                style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.875rem" }}
                aria-label="Cluster list: vulnerability ID, severity, repo, dependency, file path, finding count, affected services"
              >
                <thead>
                  <tr style={{ borderBottom: "1px solid #e5e7eb", backgroundColor: "#f9fafb" }}>
                    <th scope="col" style={{ textAlign: "left", padding: "0.5rem 0.75rem", whiteSpace: "nowrap" }}>
                      Vulnerability ID
                    </th>
                    <th scope="col" style={{ textAlign: "left", padding: "0.5rem 0.75rem", whiteSpace: "nowrap" }}>
                      Severity
                    </th>
                    <th scope="col" style={{ textAlign: "left", padding: "0.5rem 0.75rem", whiteSpace: "nowrap" }}>
                      Repo
                    </th>
                    <th scope="col" style={{ textAlign: "left", padding: "0.5rem 0.75rem", whiteSpace: "nowrap" }}>
                      Dependency
                    </th>
                    <th scope="col" style={{ textAlign: "left", padding: "0.5rem 0.75rem", whiteSpace: "nowrap" }}>
                      File path
                    </th>
                    <th scope="col" style={{ textAlign: "right", padding: "0.5rem 0.75rem", whiteSpace: "nowrap" }}>
                      Finding count
                    </th>
                    <th scope="col" style={{ textAlign: "right", padding: "0.5rem 0.75rem", whiteSpace: "nowrap" }}>
                      Affected services
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {filteredClusters.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ padding: "0.75rem" }}>
                        {summary.clusters.length === 0
                          ? "No clusters."
                          : "No clusters match the current filters."}
                      </td>
                    </tr>
                  ) : (
                    filteredClusters.map((cluster) => (
                      <tr key={cluster.vulnerability_id} style={{ borderBottom: "1px solid #e5e7eb" }}>
                        <td style={{ padding: "0.5rem 0.75rem", wordBreak: "break-all" }} title={cluster.vulnerability_id}>
                          {cluster.vulnerability_id}
                        </td>
                        <td style={{ padding: "0.5rem 0.75rem" }}>{capitalizeSeverity(cluster.severity)}</td>
                        <td style={{ padding: "0.5rem 0.75rem", wordBreak: "break-all" }}>{cluster.repo}</td>
                        <td style={{ padding: "0.5rem 0.75rem", wordBreak: "break-all" }}>{cluster.dependency ?? "—"}</td>
                        <td style={{ padding: "0.5rem 0.75rem", wordBreak: "break-all" }}>{cluster.file_path ?? "—"}</td>
                        <td style={{ padding: "0.5rem 0.75rem", textAlign: "right" }}>{cluster.finding_count}</td>
                        <td style={{ padding: "0.5rem 0.75rem", textAlign: "right" }}>{cluster.affected_services_count}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <div style={{ marginBottom: "1rem" }}>
            <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: manualTierOverride ? "0.75rem" : 0 }}>
              <input
                type="checkbox"
                checked={manualTierOverride}
                onChange={handleManualOverrideChange}
                aria-label="Override tiers before export"
                aria-checked={manualTierOverride}
              />
              <span>Override tiers before export</span>
            </label>
            {manualTierOverride && summary.clusters.length > 0 && (
              <div
                style={{
                  marginBottom: "1rem",
                  border: "1px solid #e5e7eb",
                  borderRadius: "4px",
                  overflow: "hidden",
                  maxHeight: "16rem",
                  overflowY: "auto",
                }}
                role="region"
                aria-label="Per-cluster tier override"
              >
                <table
                  style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.875rem" }}
                  aria-label="Cluster tier overrides"
                >
                  <thead>
                    <tr style={{ borderBottom: "1px solid #e5e7eb", backgroundColor: "#f9fafb" }}>
                      <th scope="col" style={{ textAlign: "left", padding: "0.5rem 0.75rem" }}>
                        Cluster
                      </th>
                      <th scope="col" style={{ textAlign: "left", padding: "0.5rem 0.75rem" }}>
                        Tier
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.clusters.map((cluster) => {
                      const displayTier =
                        tierOverrides[cluster.vulnerability_id] ??
                        severityToTierLabel(cluster.severity);
                      const vulnId =
                        cluster.vulnerability_id.length > 48
                          ? cluster.vulnerability_id.slice(0, 45) + "..."
                          : cluster.vulnerability_id;
                      return (
                        <tr key={cluster.vulnerability_id} style={{ borderBottom: "1px solid #e5e7eb" }}>
                          <td
                            style={{ padding: "0.5rem 0.75rem" }}
                            title={cluster.vulnerability_id}
                          >
                            {vulnId}
                          </td>
                          <td style={{ padding: "0.5rem 0.75rem" }}>
                            <select
                              value={displayTier}
                              onChange={(e) => handleTierChange(cluster.vulnerability_id, e.target.value)}
                              aria-label={`Tier for ${cluster.vulnerability_id}`}
                              style={{ minWidth: "6rem" }}
                            >
                              {TIER_LABELS.map((t) => (
                                <option key={t} value={t}>
                                  {t}
                                </option>
                              ))}
                            </select>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

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
            {exportStatus === "error" && exportMessage !== null && exportMessage !== "" && (
              <ErrorAlert message={exportMessage} detail={exportDetail} />
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
