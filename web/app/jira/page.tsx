"use client";

import { useState, useCallback, useEffect, useMemo } from "react";
import { createApiClient, getErrorMessage } from "@/lib/apiClient";
import { parsePastedClusters } from "@/lib/clusterValidation";
import {
  REASONING_STORAGE_KEY,
  parseStoredReasoningResponse,
  clearStoredReasoningResponse,
} from "@/lib/reasoningStorage";
import type {
  ClustersResponse,
  ReasoningResponse,
  TicketsRequest,
  JiraExportResponse,
  VulnerabilityCluster,
} from "@/lib/types";
import ErrorAlert from "@/app/components/ErrorAlert";

type JiraExportStatus = "idle" | "submitting" | "success" | "error";
type ClustersLoadStatus = "idle" | "loading" | "success" | "error";

const TIER_LABELS = ["Tier 1", "Tier 2", "Tier 3"] as const;

export default function JiraExportPage() {
  const [useDb, setUseDb] = useState(true);
  const [useReasoning, setUseReasoning] = useState(false);
  const [storedReasoning, setStoredReasoning] = useState<ReasoningResponse | null>(
    null
  );
  const [useStoredNotes, setUseStoredNotes] = useState(false);
  const [status, setStatus] = useState<JiraExportStatus>("idle");
  const [response, setResponse] = useState<JiraExportResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [clustersFromDb, setClustersFromDb] = useState<ClustersResponse | null>(null);
  const [clustersLoadStatus, setClustersLoadStatus] = useState<ClustersLoadStatus>("idle");
  const [pastedClustersText, setPastedClustersText] = useState("");
  const [parsedClusters, setParsedClusters] = useState<VulnerabilityCluster[] | null>(null);
  const [clustersParseError, setClustersParseError] = useState<string | null>(null);
  const [tierOverrides, setTierOverrides] = useState<Record<string, string>>({});

  const clustersForTierTable = useMemo(() => {
    if (useDb && clustersFromDb?.clusters?.length) return clustersFromDb.clusters;
    if (!useDb && parsedClusters?.length) return parsedClusters;
    return [];
  }, [useDb, clustersFromDb?.clusters, parsedClusters]);

  useEffect(() => {
    if (typeof sessionStorage === "undefined") return;
    try {
      const raw = sessionStorage.getItem(REASONING_STORAGE_KEY);
      const parsed = parseStoredReasoningResponse(raw);
      setStoredReasoning(parsed);
      setUseStoredNotes(parsed !== null);
    } catch {
      setStoredReasoning(null);
      setUseStoredNotes(false);
    }
  }, []);

  const fetchClusters = useCallback(async () => {
    setClustersLoadStatus("loading");
    try {
      const client = createApiClient();
      const data = await client.getClusters();
      setClustersFromDb(data);
      setClustersLoadStatus("success");
    } catch {
      setClustersLoadStatus("error");
    }
  }, []);

  useEffect(() => {
    if (!useDb) return;
    fetchClusters();
  }, [useDb, fetchClusters]);

  const handleUseDbChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setUseDb(e.target.checked);
  }, []);
  const handleUseReasoningChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setUseReasoning(e.target.checked);
  }, []);
  const handleUseStoredNotesChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setUseStoredNotes(e.target.checked);
  }, []);

  const handleClearStoredNotes = useCallback(() => {
    clearStoredReasoningResponse();
    setStoredReasoning(null);
    setUseStoredNotes(false);
  }, []);

  const handlePastedClustersChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const value = e.target.value;
    setPastedClustersText(value);
    if (value.trim().length === 0) {
      setParsedClusters(null);
      setClustersParseError(null);
      return;
    }
    const [clusters, err] = parsePastedClusters(value);
    setParsedClusters(clusters);
    setClustersParseError(err);
  }, []);

  const handleTierOverrideChange = useCallback((vulnerabilityId: string, value: string) => {
    setTierOverrides((prev) => {
      if (value === "" || !TIER_LABELS.includes(value as (typeof TIER_LABELS)[number])) {
        const next = { ...prev };
        delete next[vulnerabilityId];
        return next;
      }
      return { ...prev, [vulnerabilityId]: value };
    });
  }, []);

  const handleSubmit = useCallback(
    async (e: React.FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      let clustersToSend: VulnerabilityCluster[] | null = null;
      if (!useDb) {
        const trimmed = pastedClustersText.trim();
        if (trimmed.length === 0) {
          setClustersParseError("Paste clusters JSON when not using database.");
          return;
        }
        const [clusters, parseErr] = parsePastedClusters(trimmed);
        if (parseErr !== null || clusters === null || clusters.length === 0) {
          setClustersParseError(parseErr ?? "No clusters in pasted JSON.");
          return;
        }
        setParsedClusters(clusters);
        setClustersParseError(null);
        clustersToSend = clusters;
      }
      setStatus("submitting");
      setResponse(null);
      setErrorMessage(null);
      try {
        const useStored = useStoredNotes && storedReasoning !== null;
        const body: TicketsRequest = {
          use_db: useDb,
          use_reasoning: useStored ? false : useReasoning,
          ...(useStored && storedReasoning ? { reasoning_response: storedReasoning } : {}),
          ...(!useDb && clustersToSend && clustersToSend.length > 0 ? { clusters: clustersToSend } : {}),
          ...(Object.keys(tierOverrides).length > 0 ? { tier_overrides: tierOverrides } : {}),
        };
        const client = createApiClient();
        const data = await client.postJiraExport(body);
        setResponse(data);
        setStatus("success");
      } catch (err) {
        setErrorMessage(getErrorMessage(err));
        setStatus("error");
      }
    },
    [
      useDb,
      useReasoning,
      useStoredNotes,
      storedReasoning,
      pastedClustersText,
      tierOverrides,
    ]
  );

  const hasPartialSuccessErrors =
    status === "success" &&
    response !== null &&
    Array.isArray(response.errors) &&
    response.errors.length > 0;

  return (
    <main style={{ padding: "2rem", maxWidth: "56rem", margin: "0 auto" }}>
      <h1 style={{ fontSize: "1.25rem", marginBottom: "1rem" }}>Jira export</h1>
      {storedReasoning !== null && (
        <div
          style={{
            marginBottom: "1rem",
            padding: "0.75rem 1rem",
            backgroundColor: "#ecfdf5",
            border: "1px solid #a7f3d0",
            borderRadius: "4px",
          }}
          role="status"
          aria-live="polite"
        >
          <span>Using reasoning notes from the Reasoning page.</span>
          <button
            type="button"
            onClick={handleClearStoredNotes}
            style={{
              marginLeft: "0.75rem",
              padding: "0.25rem 0.5rem",
              fontSize: "0.875rem",
            }}
            aria-label="Clear stored reasoning notes"
          >
            Clear stored notes
          </button>
        </div>
      )}
      <form onSubmit={handleSubmit} style={{ marginBottom: "1.5rem" }}>
        <label
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
            marginBottom: "0.5rem",
          }}
        >
          <input
            type="checkbox"
            checked={useDb}
            onChange={handleUseDbChange}
            aria-label="Use current clusters from database"
            aria-checked={useDb}
          />
          <span>Use current clusters from database</span>
        </label>
        {storedReasoning !== null ? (
          <label
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              marginBottom: "0.5rem",
            }}
          >
            <input
              type="checkbox"
              checked={useStoredNotes}
              onChange={handleUseStoredNotesChange}
              aria-label="Use stored reasoning notes from Reasoning page"
              aria-checked={useStoredNotes}
            />
            <span>Use stored reasoning notes</span>
          </label>
        ) : null}
        {(!storedReasoning || !useStoredNotes) && (
          <label
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              marginBottom: "0.75rem",
            }}
          >
            <input
              type="checkbox"
              checked={useReasoning}
              onChange={handleUseReasoningChange}
              aria-label="Run reasoning before export"
              aria-checked={useReasoning}
            />
            <span>Run reasoning before export</span>
          </label>
        )}
        {!useDb && (
          <div style={{ marginBottom: "1rem" }}>
            <label
              htmlFor="jira-paste-clusters"
              style={{ display: "block", marginBottom: "0.25rem", fontWeight: 500 }}
            >
              Paste clusters JSON
            </label>
            <textarea
              id="jira-paste-clusters"
              value={pastedClustersText}
              onChange={handlePastedClustersChange}
              placeholder="Paste ClustersResponse.clusters JSON or full ClustersResponse object"
              rows={6}
              style={{
                width: "100%",
                padding: "0.5rem 0.75rem",
                fontFamily: "monospace",
                fontSize: "0.875rem",
                border: "1px solid #e5e7eb",
                borderRadius: "4px",
              }}
              aria-describedby={clustersParseError ? "jira-clusters-parse-error" : undefined}
              aria-invalid={clustersParseError !== null}
            />
            {clustersParseError !== null && (
              <p
                id="jira-clusters-parse-error"
                role="alert"
                style={{ marginTop: "0.25rem", color: "#b91c1c", fontSize: "0.875rem" }}
              >
                {clustersParseError}
              </p>
            )}
          </div>
        )}
        {clustersForTierTable.length > 0 && (
          <div style={{ marginBottom: "1rem" }}>
            <table
              style={{ width: "100%", borderCollapse: "collapse", border: "1px solid #e5e7eb" }}
              aria-label="Tier overrides per vulnerability"
            >
              <caption style={{ textAlign: "left", marginBottom: "0.5rem", fontWeight: 500 }}>
                Tier overrides (optional)
              </caption>
              <thead>
                <tr style={{ borderBottom: "1px solid #e5e7eb" }}>
                  <th
                    scope="col"
                    style={{
                      textAlign: "left",
                      padding: "0.5rem 0.75rem",
                      fontWeight: 600,
                    }}
                  >
                    Vulnerability ID
                  </th>
                  <th
                    scope="col"
                    style={{
                      textAlign: "left",
                      padding: "0.5rem 0.75rem",
                      fontWeight: 600,
                    }}
                  >
                    Tier override
                  </th>
                </tr>
              </thead>
              <tbody>
                {clustersForTierTable.map((c) => (
                  <tr key={c.vulnerability_id} style={{ borderBottom: "1px solid #e5e7eb" }}>
                    <td style={{ padding: "0.5rem 0.75rem", fontSize: "0.875rem" }}>
                      {c.vulnerability_id}
                    </td>
                    <td style={{ padding: "0.5rem 0.75rem" }}>
                      <select
                        value={tierOverrides[c.vulnerability_id] ?? ""}
                        onChange={(e) => handleTierOverrideChange(c.vulnerability_id, e.target.value)}
                        aria-label={`Tier override for ${c.vulnerability_id}`}
                        style={{
                          padding: "0.25rem 0.5rem",
                          fontSize: "0.875rem",
                          minWidth: "8rem",
                        }}
                      >
                        <option value="">No override</option>
                        {TIER_LABELS.map((tier) => (
                          <option key={tier} value={tier}>
                            {tier}
                          </option>
                        ))}
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <button
          type="submit"
          disabled={status === "submitting" || (useDb && clustersLoadStatus === "loading")}
          aria-busy={status === "submitting"}
          aria-label={
            status === "submitting" ? "Exporting to Jira" : "Export to Jira"
          }
        >
          {status === "submitting" ? "Exporting…" : "Export to Jira"}
        </button>
      </form>
      {status === "error" && errorMessage !== null && errorMessage !== "" && (
        <ErrorAlert message={errorMessage} />
      )}
      {status === "success" && response !== null && (
        <div>
          {hasPartialSuccessErrors && (
            <div
              role="alert"
              style={{
                marginBottom: "1rem",
                padding: "0.75rem 1rem",
                backgroundColor: "#fef3c7",
                border: "1px solid #f59e0b",
                borderRadius: "4px",
                color: "#92400e",
              }}
            >
              Export completed with some errors. Review the errors below.
            </div>
          )}
          {response.epics && Object.keys(response.epics).length > 0 && (
            <>
              <h2 style={{ fontSize: "1rem", marginBottom: "0.5rem" }}>Epics</h2>
              <ul style={{ listStyle: "none", padding: 0, margin: "0 0 1rem 0" }}>
                {Object.entries(response.epics).map(([tier, key]) => (
                  <li key={tier}>
                    {tier}: {key}
                  </li>
                ))}
              </ul>
            </>
          )}
          {response.issues && response.issues.length > 0 && (
            <>
              <h2 style={{ fontSize: "1rem", marginBottom: "0.5rem" }}>Issues</h2>
              <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
                {response.issues.map((issue) => (
                  <li key={issue.key} style={{ marginBottom: "0.25rem" }}>
                    {issue.key}: {issue.title} ({issue.tier})
                  </li>
                ))}
              </ul>
            </>
          )}
          {response.errors && response.errors.length > 0 && (
            <div style={{ marginTop: "1rem", color: "#b91c1c" }}>
              <h2 style={{ fontSize: "1rem", marginBottom: "0.5rem" }}>Errors</h2>
              <ul style={{ margin: 0, paddingLeft: "1.25rem" }}>
                {response.errors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </main>
  );
}
