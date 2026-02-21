"use client";

import { useState, useCallback, useEffect } from "react";
import { createApiClient, getErrorMessage } from "@/lib/apiClient";
import {
  REASONING_STORAGE_KEY,
  parseStoredReasoningResponse,
  clearStoredReasoningResponse,
} from "@/lib/reasoningStorage";
import type { ReasoningResponse, TicketsResponse } from "@/lib/types";
import ErrorAlert from "@/app/components/ErrorAlert";

type TicketsStatus = "idle" | "submitting" | "success" | "error";

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

  const handleSubmit = useCallback(
    async (e: React.FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      setStatus("submitting");
      setResponse(null);
      setErrorMessage(null);
      try {
        const client = createApiClient();
        const useStored = useStoredNotes && storedReasoning !== null;
        const body = await client.postTickets({
          use_db: useDb,
          use_reasoning: useStored ? false : useReasoning,
          reasoning_response: useStored ? storedReasoning : undefined,
        });
        setResponse(body);
        setStatus("success");
      } catch (err) {
        setErrorMessage(getErrorMessage(err));
        setStatus("error");
      }
    },
    [useDb, useReasoning, useStoredNotes, storedReasoning]
  );

  return (
    <main style={{ padding: "2rem", maxWidth: "56rem", margin: "0 auto" }}>
      <h1 style={{ fontSize: "1.25rem", marginBottom: "1rem" }}>Tickets preview</h1>
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
        <button
          type="submit"
          disabled={status === "submitting"}
          aria-busy={status === "submitting"}
          aria-label={
            status === "submitting" ? "Loading tickets" : "Load tickets"
          }
        >
          {status === "submitting" ? "Loading…" : "Load tickets"}
        </button>
      </form>
      {status === "error" &&
        errorMessage !== null &&
        errorMessage !== "" && (
          <ErrorAlert message={errorMessage} />
        )}
      {status === "success" && response !== null && (
        <div>
          <h2 style={{ fontSize: "1rem", marginBottom: "0.5rem" }}>
            Tickets ({response.tickets.length})
          </h2>
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
                <div
                  style={{ fontWeight: 600, marginBottom: "0.25rem" }}
                >
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
                <div
                  style={{
                    marginBottom: "0.5rem",
                    whiteSpace: "pre-wrap",
                  }}
                >
                  {ticket.description}
                </div>
                <div style={{ marginBottom: "0.25rem" }}>
                  <strong>Affected services:</strong>{" "}
                  {ticket.affected_services.join(", ")}
                </div>
                <div style={{ marginBottom: "0.25rem" }}>
                  <strong>Acceptance criteria:</strong>
                  <ul style={{ margin: "0.25rem 0 0 1rem", padding: 0 }}>
                    {ticket.acceptance_criteria.map((c, j) => (
                      <li key={j}>{c}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <strong>Recommended remediation:</strong>{" "}
                  {ticket.recommended_remediation}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </main>
  );
}
