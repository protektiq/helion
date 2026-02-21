"use client";

import { useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { setToken } from "@/lib/auth";
import { createApiClient, getErrorMessage, getValidationDetail } from "@/lib/apiClient";
import type { ValidationError } from "@/lib/types";
import ErrorAlert from "@/app/components/ErrorAlert";

const USERNAME_MAX = 255;
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 128;

type LoginStatus = "idle" | "submitting" | "success" | "error";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState<LoginStatus>("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorDetail, setErrorDetail] = useState<ValidationError[] | null>(null);

  const handleUsernameChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const v = (e.target.value ?? "").slice(0, USERNAME_MAX);
      setUsername(v);
    },
    []
  );

  const handlePasswordChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setPassword(e.target.value ?? "");
    },
    []
  );

  const handleSubmit = useCallback(
    async (e: React.FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      const u = username.trim();
      const p = password;
      if (u.length === 0) {
        setErrorMessage("Username is required.");
        setStatus("error");
        return;
      }
      if (p.length < PASSWORD_MIN) {
        setErrorMessage(`Password must be at least ${PASSWORD_MIN} characters.`);
        setStatus("error");
        return;
      }
      if (p.length > PASSWORD_MAX) {
        setErrorMessage(`Password must be at most ${PASSWORD_MAX} characters.`);
        setStatus("error");
        return;
      }

      setStatus("submitting");
      setErrorMessage(null);
      setErrorDetail(null);
      try {
        const client = createApiClient();
        const data = await client.login({ username: u, password: p });
        setToken(data.access_token);
        setStatus("success");
        router.push("/");
      } catch (err) {
        setErrorMessage(getErrorMessage(err));
        setErrorDetail(getValidationDetail(err));
        setStatus("error");
      }
    },
    [username, password, router]
  );

  return (
    <main style={{ padding: "2rem", maxWidth: "28rem", margin: "0 auto" }}>
      <h1 style={{ fontSize: "1.25rem", marginBottom: "1rem" }}>Login</h1>
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: "1rem" }}>
          <label htmlFor="login-username" style={{ display: "block", marginBottom: "0.5rem" }}>
            Username
          </label>
          <input
            id="login-username"
            type="text"
            value={username}
            onChange={handleUsernameChange}
            maxLength={USERNAME_MAX}
            autoComplete="username"
            aria-label="Username"
            disabled={status === "submitting"}
            style={{ width: "100%", maxWidth: "20rem", padding: "0.375rem 0.5rem" }}
          />
        </div>
        <div style={{ marginBottom: "1rem" }}>
          <label htmlFor="login-password" style={{ display: "block", marginBottom: "0.5rem" }}>
            Password
          </label>
          <input
            id="login-password"
            type="password"
            value={password}
            onChange={handlePasswordChange}
            minLength={PASSWORD_MIN}
            maxLength={PASSWORD_MAX}
            autoComplete="current-password"
            aria-label="Password"
            disabled={status === "submitting"}
            style={{ width: "100%", maxWidth: "20rem", padding: "0.375rem 0.5rem" }}
          />
        </div>
        <button
          type="submit"
          disabled={status === "submitting"}
          aria-busy={status === "submitting"}
          aria-label={status === "submitting" ? "Logging in" : "Log in"}
        >
          {status === "submitting" ? "Logging in…" : "Log in"}
        </button>
      </form>
      {status === "error" && errorMessage !== null && errorMessage !== "" && (
        <ErrorAlert message={errorMessage} detail={errorDetail} />
      )}
      <p
        aria-live="polite"
        style={{
          marginTop: "1rem",
          fontSize: "0.875rem",
          color: "#6b7280",
        }}
      >
        The token is stored locally in this browser only.
      </p>
    </main>
  );
}
