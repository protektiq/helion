"use client";

import { useState, useCallback } from "react";
import { createApiClient } from "@/lib/apiClient";
import { getStoredToken } from "@/lib/api";
import type { JiraExportResponse } from "@/lib/types";

type JiraExportStatus = "idle" | "submitting" | "success" | "error";

export default function JiraExportPage() {
  const [useDb, setUseDb] = useState(true);
  const [useReasoning, setUseReasoning] = useState(false);
  const [status, setStatus] = useState<JiraExportStatus>("idle");
  const [response, setResponse] = useState<JiraExportResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleUseDbChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setUseDb(e.target.checked);
  }, []);
  const handleUseReasoningChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setUseReasoning(e.target.checked);
  }, []);

  const handleSubmit = useCallback(
    async (e: React.FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      setStatus("submitting");
      setResponse(null);
      setErrorMessage(null);
      try {
        const client = createApiClient({ token: getStoredToken() });
        const data = await client.postJiraExport({ use_db: useDb, use_reasoning: useReasoning });
        setResponse(data);
        setStatus("success");
      } catch (err) {
        setErrorMessage(
          err instanceof Error ? err.message : "Network or request failed."
        );
        setStatus("error");
      }
    },
    [useDb, useReasoning]
  );

  return (
    <main style={{ padding: "2rem", maxWidth: "48rem", margin: "0 auto" }}>
      <h1 style={{ fontSize: "1.25rem", marginBottom: "1rem" }}>Jira export</h1>
      <form onSubmit={handleSubmit} style={{ marginBottom: "1.5rem" }}>
        <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
          <input
            type="checkbox"
            checked={useDb}
            onChange={handleUseDbChange}
            aria-label="Use current clusters from database"
            aria-checked={useDb}
          />
          <span>Use current clusters from database</span>
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.75rem" }}>
          <input
            type="checkbox"
            checked={useReasoning}
            onChange={handleUseReasoningChange}
            aria-label="Run reasoning before export"
            aria-checked={useReasoning}
          />
          <span>Run reasoning before export</span>
        </label>
        <button
          type="submit"
          disabled={status === "submitting"}
          aria-busy={status === "submitting"}
          aria-label={status === "submitting" ? "Exporting to Jira" : "Export to Jira"}
        >
          {status === "submitting" ? "Exporting…" : "Export to Jira"}
        </button>
      </form>
      {status === "error" && errorMessage !== null && (
        <p role="alert" style={{ color: "#b91c1c", marginBottom: "1rem" }}>
          {errorMessage}
        </p>
      )}
      {status === "success" && response !== null && (
        <div>
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
