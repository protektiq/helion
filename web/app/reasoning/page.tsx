"use client";

import { useState, useCallback } from "react";
import { createApiClient } from "@/lib/apiClient";
import { getStoredToken } from "@/lib/api";
import type { ReasoningResponse } from "@/lib/types";

type ReasoningStatus = "idle" | "submitting" | "success" | "error";

export default function ReasoningPage() {
  const [useDb, setUseDb] = useState(true);
  const [status, setStatus] = useState<ReasoningStatus>("idle");
  const [response, setResponse] = useState<ReasoningResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleUseDbChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setUseDb(e.target.checked);
  }, []);

  const handleSubmit = useCallback(
    async (e: React.FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      setStatus("submitting");
      setResponse(null);
      setErrorMessage(null);
      try {
        const client = createApiClient({ token: getStoredToken() });
        const body = await client.postReasoning({ clusters: [], use_db: useDb });
        setResponse(body);
        setStatus("success");
      } catch (err) {
        setErrorMessage(
          err instanceof Error ? err.message : "Network or request failed."
        );
        setStatus("error");
      }
    },
    [useDb]
  );

  return (
    <main style={{ padding: "2rem", maxWidth: "48rem", margin: "0 auto" }}>
      <h1 style={{ fontSize: "1.25rem", marginBottom: "1rem" }}>Reasoning</h1>
      <form onSubmit={handleSubmit} style={{ marginBottom: "1.5rem" }}>
        <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.75rem" }}>
          <input
            type="checkbox"
            checked={useDb}
            onChange={handleUseDbChange}
            aria-label="Use current clusters from database"
            aria-checked={useDb}
          />
          <span>Use current clusters from database</span>
        </label>
        <button
          type="submit"
          disabled={status === "submitting"}
          aria-busy={status === "submitting"}
          aria-label={status === "submitting" ? "Running reasoning" : "Run reasoning"}
        >
          {status === "submitting" ? "Running…" : "Run reasoning"}
        </button>
      </form>
      {status === "error" && errorMessage !== null && (
        <p role="alert" style={{ color: "#b91c1c", marginBottom: "1rem" }}>
          {errorMessage}
        </p>
      )}
      {status === "success" && response !== null && (
        <div>
          <h2 style={{ fontSize: "1rem", marginBottom: "0.5rem" }}>Summary</h2>
          <p style={{ marginBottom: "1rem", whiteSpace: "pre-wrap" }}>{response.summary || "—"}</p>
          <h2 style={{ fontSize: "1rem", marginBottom: "0.5rem" }}>Cluster notes</h2>
          <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
            {response.cluster_notes.map((note) => (
              <li
                key={note.vulnerability_id}
                style={{
                  borderBottom: "1px solid #e5e7eb",
                  padding: "0.75rem 0",
                }}
              >
                <strong>{note.vulnerability_id}</strong>
                {note.assigned_tier != null && (
                  <span style={{ marginLeft: "0.5rem" }}>Tier {note.assigned_tier}</span>
                )}
                {note.override_applied && (
                  <span style={{ marginLeft: "0.5rem", color: "#6b7280" }}>({note.override_applied})</span>
                )}
                <div style={{ marginTop: "0.25rem" }}>Priority: {note.priority}</div>
                <div style={{ marginTop: "0.25rem", color: "#374151" }}>{note.reasoning}</div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </main>
  );
}
