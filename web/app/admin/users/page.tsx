"use client";

import { useState, useCallback, useEffect } from "react";
import { createApiClient, getErrorMessage } from "@/lib/apiClient";
import type { UsersListResponse } from "@/lib/types";
import ErrorAlert from "@/app/components/ErrorAlert";

type UsersStatus = "idle" | "loading" | "success" | "error";

type ApiError = Error & { status?: number };

export default function AdminUsersPage() {
  const [status, setStatus] = useState<UsersStatus>("idle");
  const [data, setData] = useState<UsersListResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchUsers = useCallback(async () => {
    setStatus("loading");
    setErrorMessage(null);
    setData(null);
    try {
      const client = createApiClient();
      const body = await client.listUsers();
      setData(body);
      setStatus("success");
    } catch (err) {
      const apiErr = err as ApiError;
      if (apiErr.status === 401 || apiErr.status === 403) {
        setErrorMessage("Admin only");
      } else {
        setErrorMessage(getErrorMessage(err));
      }
      setStatus("error");
    }
  }, []);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  return (
    <main style={{ padding: "2rem", maxWidth: "40rem", margin: "0 auto" }}>
      <h1 style={{ fontSize: "1.25rem", marginBottom: "1rem" }}>Admin users</h1>
      {status === "loading" && (
        <p role="status" aria-live="polite">
          Loading…
        </p>
      )}
      {status === "error" && errorMessage !== null && (
        <ErrorAlert
          message={errorMessage}
          onRetry={fetchUsers}
          retryLabel="Retry load users"
        />
      )}
      {status === "success" && data !== null && (
        <table
          style={{ width: "100%", borderCollapse: "collapse" }}
          aria-label="Users list"
        >
          <caption style={{ textAlign: "left", marginBottom: "0.5rem" }}>
            All users (admin only)
          </caption>
          <thead>
            <tr style={{ borderBottom: "1px solid #e5e7eb" }}>
              <th scope="col" style={{ textAlign: "left", padding: "0.5rem 0.75rem" }}>
                ID
              </th>
              <th scope="col" style={{ textAlign: "left", padding: "0.5rem 0.75rem" }}>
                Username
              </th>
              <th scope="col" style={{ textAlign: "left", padding: "0.5rem 0.75rem" }}>
                Role
              </th>
            </tr>
          </thead>
          <tbody>
            {data.users.map((user) => (
              <tr key={user.id} style={{ borderBottom: "1px solid #e5e7eb" }}>
                <td style={{ padding: "0.5rem 0.75rem" }}>{user.id}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>{user.username}</td>
                <td style={{ padding: "0.5rem 0.75rem" }}>{user.role}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
