"use client";

import { useState, useCallback, useEffect } from "react";
import { AUTH_TOKEN_KEY } from "@/lib/api";

const TOKEN_MAX_LENGTH = 4096;

export default function AuthTokenInput() {
  const [token, setToken] = useState("");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      const stored = localStorage.getItem(AUTH_TOKEN_KEY);
      setToken(typeof stored === "string" ? stored : "");
    } catch {
      setToken("");
    }
  }, []);

  const handleSave = useCallback(() => {
    if (typeof window === "undefined") return;
    const trimmed = typeof token === "string" ? token.trim() : "";
    try {
      if (trimmed.length === 0) {
        localStorage.removeItem(AUTH_TOKEN_KEY);
      } else {
        const toStore = trimmed.length > TOKEN_MAX_LENGTH ? trimmed.slice(0, TOKEN_MAX_LENGTH) : trimmed;
        localStorage.setItem(AUTH_TOKEN_KEY, toStore);
      }
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {
      setSaved(false);
    }
  }, [token]);

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value ?? "";
    setToken(value);
  }, []);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Enter") {
        e.preventDefault();
        handleSave();
      }
    },
    [handleSave]
  );

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "0.5rem",
        flexShrink: 0,
      }}
    >
      <label
        htmlFor="helion-token-input"
        style={{ position: "absolute", width: 1, height: 1, overflow: "hidden", clip: "rect(0,0,0,0)" }}
      >
        API token (paste JWT for authenticated requests)
      </label>
      <input
        id="helion-token-input"
        type="password"
        value={token}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        onBlur={handleSave}
        placeholder="Paste token"
        aria-label="API token (paste JWT for authenticated requests)"
        aria-describedby="helion-token-hint"
        maxLength={TOKEN_MAX_LENGTH}
        style={{
          minWidth: "8rem",
          maxWidth: "16rem",
          padding: "0.25rem 0.5rem",
          fontSize: "0.875rem",
          border: "1px solid #d1d5db",
          borderRadius: "4px",
          background: "#fff",
          color: "#111",
        }}
      />
      <button
        type="button"
        onClick={handleSave}
        aria-label="Save token"
        style={{
          padding: "0.25rem 0.5rem",
          fontSize: "0.875rem",
          border: "1px solid #d1d5db",
          borderRadius: "4px",
          background: "#f9fafb",
          color: "#374151",
          cursor: "pointer",
        }}
      >
        {saved ? "Saved" : "Save"}
      </button>
      <span
        id="helion-token-hint"
        style={{ position: "absolute", width: 1, height: 1, overflow: "hidden", clip: "rect(0,0,0,0)" }}
      >
        Token is stored in this browser only and sent as Bearer token to the API.
      </span>
    </div>
  );
}
