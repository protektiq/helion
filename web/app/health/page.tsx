"use client";

import { useState, useCallback, useEffect } from "react";
import { createApiClient } from "@/lib/apiClient";
import type { HealthResponse } from "@/lib/types";

type HealthStatus = "idle" | "loading" | "success" | "error";

export default function HealthPage() {
  const [status, setStatus] = useState<HealthStatus>("idle");
  const [data, setData] = useState<HealthResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchHealth = useCallback(async () => {
    setStatus("loading");
    setErrorMessage(null);
    setData(null);
    try {
      const client = createApiClient();
      const body = await client.getHealth();
      setData(body);
      setStatus("success");
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : "Network or request failed."
      );
      setStatus("error");
    }
  }, []);

  useEffect(() => {
    fetchHealth();
  }, [fetchHealth]);

  return (
    <main style={{ padding: "2rem", maxWidth: "32rem", margin: "0 auto" }}>
      <h1 style={{ fontSize: "1.25rem", marginBottom: "1rem" }}>Health</h1>
      {status === "loading" && (
        <p role="status" aria-live="polite">
          Loading…
        </p>
      )}
      {status === "error" && (
        <div role="alert" style={{ marginBottom: "1rem", color: "#b91c1c" }}>
          <p>{errorMessage}</p>
          <button type="button" onClick={fetchHealth} aria-label="Retry health check">
            Retry
          </button>
        </div>
      )}
      {status === "success" && data !== null && (
        <dl style={{ margin: 0 }}>
          <dt style={{ fontWeight: 600, marginTop: "0.5rem" }}>Environment</dt>
          <dd style={{ marginLeft: 0, marginTop: "0.25rem" }}>{data.environment}</dd>
          {data.status !== undefined && (
            <>
              <dt style={{ fontWeight: 600, marginTop: "0.5rem" }}>Status</dt>
              <dd style={{ marginLeft: 0, marginTop: "0.25rem" }}>{data.status}</dd>
            </>
          )}
          {data.database !== undefined && data.database !== null && (
            <>
              <dt style={{ fontWeight: 600, marginTop: "0.5rem" }}>Database</dt>
              <dd style={{ marginLeft: 0, marginTop: "0.25rem" }}>{data.database}</dd>
            </>
          )}
        </dl>
      )}
    </main>
  );
}
