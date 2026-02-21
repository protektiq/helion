"use client";

import { useState, useEffect, useCallback } from "react";
import { createApiClient, getErrorMessage } from "@/lib/apiClient";
import type { HealthResponse } from "@/lib/types";

const KNOWN_ENV_MAX_LENGTH = 32;
const DB_CONNECTED = "connected";
const DB_DISCONNECTED = "disconnected";

type BadgeStatus = "idle" | "loading" | "success" | "error";

function sanitizeEnvironment(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) return "—";
  const trimmed = value.trim();
  if (trimmed.length > KNOWN_ENV_MAX_LENGTH) return trimmed.slice(0, KNOWN_ENV_MAX_LENGTH);
  return trimmed;
}

function sanitizeDatabase(value: unknown): "connected" | "disconnected" | "—" {
  if (value === DB_CONNECTED) return "connected";
  if (value === DB_DISCONNECTED) return "disconnected";
  return "—";
}

export default function EnvironmentBadge() {
  const [status, setStatus] = useState<BadgeStatus>("idle");
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
      setErrorMessage(getErrorMessage(err));
      setStatus("error");
    }
  }, []);

  useEffect(() => {
    fetchHealth();
  }, [fetchHealth]);

  const badgeStyle: React.CSSProperties = {
    fontSize: "0.75rem",
    color: "#6b7280",
    display: "flex",
    alignItems: "center",
    gap: "0.75rem",
    flexShrink: 0,
  };

  if (status === "loading") {
    return (
      <div
        role="status"
        aria-live="polite"
        aria-label="Environment and database status loading"
        style={badgeStyle}
      >
        <span>Env: …</span>
        <span>DB: …</span>
      </div>
    );
  }

  if (status === "error") {
    const label = errorMessage ?? "API unreachable";
    return (
      <div
        role="status"
        aria-live="polite"
        aria-label={`Health check failed: ${label}`}
        style={badgeStyle}
      >
        <span>Env: —</span>
        <span>DB: —</span>
      </div>
    );
  }

  if (status === "success" && data !== null) {
    const env = sanitizeEnvironment(data.environment);
    const db = sanitizeDatabase(data.database);
    const dbLabel = db === "—" ? "—" : db;
    const ariaLabel = `Environment ${env}, database ${dbLabel}`;
    return (
      <div
        role="status"
        aria-live="polite"
        aria-label={ariaLabel}
        style={badgeStyle}
      >
        <span>Env: {env}</span>
        <span>DB: {dbLabel}</span>
      </div>
    );
  }

  return (
    <div role="status" aria-live="polite" aria-label="Environment and database status unknown" style={badgeStyle}>
      <span>Env: —</span>
      <span>DB: —</span>
    </div>
  );
}
