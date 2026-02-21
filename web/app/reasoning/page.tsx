"use client";

import { useState, useCallback } from "react";
import Link from "next/link";
import { createApiClient, getErrorMessage, getValidationDetail } from "@/lib/apiClient";
import { setStoredReasoningResponse } from "@/lib/reasoningStorage";
import {
  parsePastedClusters,
  rankClusters,
  MAX_CLUSTERS,
} from "@/lib/clusterValidation";
import type { ReasoningResponse, ValidationError } from "@/lib/types";
import ErrorAlert from "@/app/components/ErrorAlert";

type ReasoningStatus = "idle" | "submitting" | "success" | "error";

const MAX_CLUSTERS_CAP = 100;

export default function ReasoningPage() {
  const [useDb, setUseDb] = useState(true);
  const [maxClusters, setMaxClusters] = useState(100);
  const [clustersJson, setClustersJson] = useState("");
  const [status, setStatus] = useState<ReasoningStatus>("idle");
  const [response, setResponse] = useState<ReasoningResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorDetail, setErrorDetail] = useState<ValidationError[] | null>(null);
  const [storedConfirm, setStoredConfirm] = useState(false);
  const [dbSliceInfo, setDbSliceInfo] = useState<{
    total: number;
    sending: number;
  } | null>(null);

  const effectiveMaxClusters = Math.min(
    MAX_CLUSTERS_CAP,
    Math.max(1, maxClusters)
  );

  const handleUseDbChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setUseDb(e.target.checked);
  }, []);

  const handleClustersJsonChange = useCallback(
    (e: React.ChangeEvent<HTMLTextAreaElement>) => {
      setClustersJson(e.target.value);
    },
    []
  );

  const clampMaxClusters = useCallback((value: number): number => {
    if (Number.isNaN(value)) return MAX_CLUSTERS_CAP;
    return Math.min(MAX_CLUSTERS_CAP, Math.max(1, Math.floor(value)));
  }, []);

  const handleMaxClustersChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const next = clampMaxClusters(Number(e.target.value));
      setMaxClusters(next);
    },
    [clampMaxClusters]
  );

  const handleMaxClustersBlur = useCallback(
    (e: React.FocusEvent<HTMLInputElement>) => {
      const next = clampMaxClusters(Number(e.target.value));
      setMaxClusters(next);
    },
    [clampMaxClusters]
  );

  const handleSubmit = useCallback(
    async (e: React.FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      setStoredConfirm(false);
      setDbSliceInfo(null);
      if (!useDb) {
        const [clusters, parseError] = parsePastedClusters(clustersJson);
        if (parseError !== null || clusters === null) {
          setErrorMessage(parseError ?? "Failed to parse clusters.");
          setErrorDetail(null);
          setStatus("error");
          setResponse(null);
          return;
        }
        setStatus("submitting");
        setResponse(null);
        setErrorMessage(null);
        setErrorDetail(null);
        try {
          const client = createApiClient();
          const body = await client.postReasoning({
            clusters,
            use_db: false,
          });
          setResponse(body);
          setStatus("success");
        } catch (err) {
          setErrorMessage(getErrorMessage(err));
          setErrorDetail(getValidationDetail(err));
          setStatus("error");
        }
        return;
      }
      setStatus("submitting");
      setResponse(null);
      setErrorMessage(null);
      setErrorDetail(null);
      const client = createApiClient();
      try {
        const clustersResponse = await client.getClusters();
        const ranked = rankClusters(clustersResponse.clusters);
        const clustersToSend =
          ranked.length > effectiveMaxClusters
            ? ranked.slice(0, effectiveMaxClusters)
            : ranked;
        if (ranked.length > effectiveMaxClusters) {
          setDbSliceInfo({
            total: ranked.length,
            sending: clustersToSend.length,
          });
        }
        const body = await client.postReasoning({
          clusters: clustersToSend,
          use_db: false,
        });
        setResponse(body);
        setStatus("success");
      } catch (err) {
        setErrorMessage(getErrorMessage(err));
        setErrorDetail(getValidationDetail(err));
        setStatus("error");
      }
    },
    [useDb, clustersJson, effectiveMaxClusters]
  );

  const handleUseNotesForTickets = useCallback(() => {
    if (response === null) return;
    setStoredReasoningResponse(response);
    setStoredConfirm(true);
  }, [response]);

  return (
    <main style={{ padding: "2rem", maxWidth: "48rem", margin: "0 auto" }}>
      <h1 style={{ fontSize: "1.25rem", marginBottom: "1rem" }}>Reasoning</h1>
      <form onSubmit={handleSubmit} style={{ marginBottom: "1.5rem" }}>
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
            checked={useDb}
            onChange={handleUseDbChange}
            aria-label="Use current clusters from database"
            aria-checked={useDb}
          />
          <span>Use current clusters from database</span>
        </label>
        {useDb && (
          <div style={{ marginBottom: "0.75rem" }}>
            <label
              htmlFor="reasoning-max-clusters"
              style={{ display: "block", marginBottom: "0.25rem" }}
            >
              Max clusters
            </label>
            <input
              id="reasoning-max-clusters"
              type="number"
              min={1}
              max={MAX_CLUSTERS_CAP}
              value={maxClusters}
              onChange={handleMaxClustersChange}
              onBlur={handleMaxClustersBlur}
              aria-label="Max clusters (1–100; backend allows at most 100)"
              aria-describedby="reasoning-max-clusters-hint"
              style={{
                width: "100%",
                maxWidth: "6rem",
                padding: "0.375rem 0.5rem",
                fontSize: "0.875rem",
                border: "1px solid #d1d5db",
                borderRadius: "4px",
              }}
            />
            <span
              id="reasoning-max-clusters-hint"
              style={{ fontSize: "0.75rem", color: "#6b7280", display: "block", marginTop: "0.25rem" }}
            >
              1–100; backend allows at most 100.
            </span>
          </div>
        )}
        {!useDb && (
          <div style={{ marginBottom: "0.75rem" }}>
            <label
              htmlFor="reasoning-clusters-json"
              style={{ display: "block", marginBottom: "0.25rem" }}
            >
              Paste clusters JSON
            </label>
            <textarea
              id="reasoning-clusters-json"
              value={clustersJson}
              onChange={handleClustersJsonChange}
              placeholder="Paste ClustersResponse.clusters JSON or full ClustersResponse object"
              rows={8}
              style={{
                width: "100%",
                padding: "0.5rem",
                fontFamily: "monospace",
                fontSize: "0.875rem",
                border: "1px solid #d1d5db",
                borderRadius: "4px",
              }}
              aria-describedby="reasoning-clusters-hint"
            />
            <span
              id="reasoning-clusters-hint"
              style={{ fontSize: "0.75rem", color: "#6b7280" }}
            >
              ClustersResponse with &quot;clusters&quot; array or raw array of
              clusters (max {MAX_CLUSTERS}).
            </span>
          </div>
        )}
        <button
          type="submit"
          disabled={status === "submitting"}
          aria-busy={status === "submitting"}
          aria-label={
            status === "submitting" ? "Running reasoning" : "Run reasoning"
          }
        >
          {status === "submitting" ? "Running…" : "Run reasoning"}
        </button>
      </form>
      {dbSliceInfo !== null && (
        <div
          role="status"
          aria-live="polite"
          style={{
            marginBottom: "1rem",
            padding: "0.75rem 1rem",
            backgroundColor: "#eff6ff",
            border: "1px solid #bfdbfe",
            borderRadius: "4px",
            fontSize: "0.875rem",
            color: "#1e40af",
          }}
        >
          <div>
            {dbSliceInfo.total} clusters found. Running reasoning on top{" "}
            {dbSliceInfo.sending} by severity/CVSS.
          </div>
          <div style={{ marginTop: "0.25rem" }}>
            Sending {dbSliceInfo.sending} / {dbSliceInfo.total} clusters.
          </div>
        </div>
      )}
      {status === "error" &&
        errorMessage !== null &&
        errorMessage !== "" && (
          <ErrorAlert message={errorMessage} detail={errorDetail} />
        )}
      {status === "success" && response !== null && (
        <div>
          <h2 style={{ fontSize: "1rem", marginBottom: "0.5rem" }}>Summary</h2>
          <p
            style={{
              marginBottom: "1rem",
              whiteSpace: "pre-wrap",
            }}
          >
            {response.summary || "—"}
          </p>
          <h2 style={{ fontSize: "1rem", marginBottom: "0.5rem" }}>
            Cluster notes
          </h2>
          <table
            style={{
              width: "100%",
              borderCollapse: "collapse",
              border: "1px solid #e5e7eb",
            }}
            aria-label="Per-cluster notes: vulnerability id, priority, tier, override, reasoning"
          >
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
                  vulnerability_id
                </th>
                <th
                  scope="col"
                  style={{
                    textAlign: "left",
                    padding: "0.5rem 0.75rem",
                    fontWeight: 600,
                  }}
                >
                  priority
                </th>
                <th
                  scope="col"
                  style={{
                    textAlign: "left",
                    padding: "0.5rem 0.75rem",
                    fontWeight: 600,
                  }}
                >
                  assigned_tier
                </th>
                <th
                  scope="col"
                  style={{
                    textAlign: "left",
                    padding: "0.5rem 0.75rem",
                    fontWeight: 600,
                  }}
                >
                  override_applied
                </th>
                <th
                  scope="col"
                  style={{
                    textAlign: "left",
                    padding: "0.5rem 0.75rem",
                    fontWeight: 600,
                  }}
                >
                  reasoning
                </th>
              </tr>
            </thead>
            <tbody>
              {response.cluster_notes.map((note) => (
                <tr
                  key={note.vulnerability_id}
                  style={{ borderBottom: "1px solid #e5e7eb" }}
                >
                  <td
                    style={{
                      padding: "0.5rem 0.75rem",
                      verticalAlign: "top",
                    }}
                  >
                    {note.vulnerability_id}
                  </td>
                  <td
                    style={{
                      padding: "0.5rem 0.75rem",
                      verticalAlign: "top",
                    }}
                  >
                    {note.priority}
                  </td>
                  <td
                    style={{
                      padding: "0.5rem 0.75rem",
                      verticalAlign: "top",
                    }}
                  >
                    {note.assigned_tier != null ? note.assigned_tier : "—"}
                  </td>
                  <td
                    style={{
                      padding: "0.5rem 0.75rem",
                      verticalAlign: "top",
                      color: "#6b7280",
                    }}
                  >
                    {note.override_applied ?? "—"}
                  </td>
                  <td
                    style={{
                      padding: "0.5rem 0.75rem",
                      verticalAlign: "top",
                      color: "#374151",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {note.reasoning}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ marginTop: "1rem" }}>
            <button
              type="button"
              onClick={handleUseNotesForTickets}
              aria-label="Store these notes for use on the Tickets page"
            >
              Use these notes for Tickets
            </button>
            {storedConfirm && (
              <span style={{ marginLeft: "0.75rem", color: "#059669" }}>
                Stored.{" "}
                <Link
                  href="/tickets"
                  style={{ color: "#2563eb", textDecoration: "underline" }}
                >
                  Go to Tickets
                </Link>
              </span>
            )}
          </div>
        </div>
      )}
    </main>
  );
}
