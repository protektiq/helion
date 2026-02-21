"use client";

import { useState, useCallback, useEffect, useMemo } from "react";
import Link from "next/link";
import { createApiClient, getErrorMessage, getValidationDetail } from "@/lib/apiClient";
import { parsePastedClusters } from "@/lib/clusterValidation";
import {
  REASONING_STORAGE_KEY,
  parseStoredReasoningResponse,
  clearStoredReasoningResponse,
} from "@/lib/reasoningStorage";
import { setStoredTierOverrides } from "@/lib/tierOverridesStorage";
import type {
  ClustersResponse,
  ReasoningResponse,
  TicketsRequest,
  TicketsResponse,
  ValidationError,
  VulnerabilityCluster,
} from "@/lib/types";
import ErrorAlert from "@/app/components/ErrorAlert";

type TicketsStatus = "idle" | "submitting" | "success" | "error";
type ClustersLoadStatus = "idle" | "loading" | "success" | "error";

const TIER_LABELS = ["Tier 1", "Tier 2", "Tier 3"] as const;

export default function TicketsPage() {
  const [useDb, setUseDb] = useState(true);
  const [useReasoning, setUseReasoning] = useState(false);
  const [storedReasoning, setStoredReasoning] = useState<ReasoningResponse | null>(
    null
  );
  const [useStoredNotes, setUseStoredNotes] = useState(false);
  const [status, setStatus] = useState<TicketsStatus>("idle");
  const [response, setResponse] = useState<TicketsResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorDetail, setErrorDetail] = useState<ValidationError[] | null>(null);

  const [clustersFromDb, setClustersFromDb] = useState<ClustersResponse | null>(null);
  const [clustersLoadStatus, setClustersLoadStatus] = useState<ClustersLoadStatus>("idle");
  const [pastedClustersText, setPastedClustersText] = useState("");
  const [parsedClusters, setParsedClusters] = useState<VulnerabilityCluster[] | null>(null);
  const [clustersParseError, setClustersParseError] = useState<string | null>(null);
  const [tierOverrides, setTierOverrides] = useState<Record<string, string>>({});
  const [lastRequestPayload, setLastRequestPayload] = useState<TicketsRequest | null>(null);
  const [copyFeedback, setCopyFeedback] = useState<string | null>(null);

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

  const handleCopyJson = useCallback(() => {
    if (lastRequestPayload === null) return;
    const json = JSON.stringify(lastRequestPayload, null, 2);
    navigator.clipboard.writeText(json).then(
      () => {
        setCopyFeedback("Copied to clipboard");
        setTimeout(() => setCopyFeedback(null), 2000);
      },
      () => setCopyFeedback("Copy failed")
    );
  }, [lastRequestPayload]);

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
      setErrorDetail(null);
      try {
        const useStored = useStoredNotes && storedReasoning !== null;
        const body: TicketsRequest = {
          clusters: useDb ? [] : (clustersToSend ?? []),
          use_db: useDb,
          use_reasoning: useStored ? false : useReasoning,
          ...(useStored && storedReasoning ? { reasoning_response: storedReasoning } : {}),
          ...(Object.keys(tierOverrides).length > 0 ? { tier_overrides: tierOverrides } : {}),
        };
        const client = createApiClient();
        const result = await client.postTickets(body);
        setLastRequestPayload(body);
        setResponse(result);
        setStatus("success");
      } catch (err) {
        setErrorMessage(getErrorMessage(err));
        setErrorDetail(getValidationDetail(err));
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

  const flowNavStyle = { color: "#2563eb", textDecoration: "underline" as const };

  return (
    <main style={{ padding: "2rem", maxWidth: "56rem", margin: "0 auto" }}>
      <h1 style={{ fontSize: "1.25rem", marginBottom: "1rem" }}>Tickets preview</h1>
      <nav style={{ marginBottom: "1.5rem" }}>
        <Link href="/results" style={flowNavStyle} aria-label="Go to Results">
          Results
        </Link>
        {" · "}
        <Link
          href="/jira"
          style={flowNavStyle}
          aria-label="Go to Jira Export"
          onClick={() => setStoredTierOverrides(tierOverrides)}
        >
          Jira Export
        </Link>
      </nav>
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
              aria-label="Run reasoning and attach to tickets"
              aria-checked={useReasoning}
            />
            <span>Run reasoning and attach to tickets</span>
          </label>
        )}
        {!useDb && (
          <div style={{ marginBottom: "1rem" }}>
            <label
              htmlFor="tickets-paste-clusters"
              style={{ display: "block", marginBottom: "0.25rem", fontWeight: 500 }}
            >
              Paste clusters JSON
            </label>
            <textarea
              id="tickets-paste-clusters"
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
              aria-describedby={clustersParseError ? "tickets-clusters-parse-error" : undefined}
              aria-invalid={clustersParseError !== null}
            />
            {clustersParseError !== null && (
              <p
                id="tickets-clusters-parse-error"
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
            status === "submitting" ? "Generating tickets" : "Generate tickets"
          }
        >
          {status === "submitting" ? "Loading…" : "Generate tickets"}
        </button>
      </form>
      {status === "error" &&
        errorMessage !== null &&
        errorMessage !== "" && (
          <ErrorAlert message={errorMessage} detail={errorDetail} />
        )}
      {status === "success" && response !== null && (
        <div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "1rem",
              marginBottom: "0.75rem",
              flexWrap: "wrap",
            }}
          >
            <h2 style={{ fontSize: "1rem", margin: 0 }}>
              Tickets ({response.tickets.length})
            </h2>
            <button
              type="button"
              onClick={handleCopyJson}
              disabled={lastRequestPayload === null}
              aria-label="Copy request payload as JSON"
              style={{
                padding: "0.25rem 0.5rem",
                fontSize: "0.875rem",
              }}
            >
              Copy JSON
            </button>
            {copyFeedback !== null && (
              <span
                role="status"
                aria-live="polite"
                style={{ fontSize: "0.875rem", color: "#6b7280" }}
              >
                {copyFeedback}
              </span>
            )}
          </div>
          <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
            {response.tickets.map((ticket, i) => (
              <li
                key={i}
                style={{
                  border: "1px solid #e5e7eb",
                  borderRadius: "4px",
                  padding: "1rem",
                  marginBottom: "1rem",
                }}
              >
                <div style={{ fontWeight: 600, marginBottom: "0.25rem" }}>
                  {ticket.title}
                </div>
                <div
                  style={{
                    fontSize: "0.875rem",
                    color: "#6b7280",
                    marginBottom: "0.5rem",
                  }}
                >
                  {ticket.risk_tier_label}
                </div>
                <div style={{ marginBottom: "0.5rem" }}>
                  <strong>Affected services:</strong>{" "}
                  {ticket.affected_services.join(", ")}
                </div>
                <div style={{ marginBottom: "0.5rem" }}>
                  <strong>Recommended remediation:</strong>{" "}
                  {ticket.recommended_remediation}
                </div>
                <div>
                  <strong>Acceptance criteria:</strong>
                  <ul style={{ margin: "0.25rem 0 0 1rem", padding: 0 }}>
                    {ticket.acceptance_criteria.map((c, j) => (
                      <li key={j}>{c}</li>
                    ))}
                  </ul>
                </div>
                <div
                  style={{
                    marginTop: "0.5rem",
                    whiteSpace: "pre-wrap",
                    fontSize: "0.875rem",
                    color: "#6b7280",
                  }}
                >
                  {ticket.description}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </main>
  );
}
