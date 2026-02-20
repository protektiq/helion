"use client";

import { useState, useCallback, useEffect } from "react";
import { getApiBaseUrl, getAuthHeaders } from "@/lib/api";

type UserListItem = {
  id: number;
  username: string;
  role: string;
};

type UsersListResponse = {
  users: UserListItem[];
};

type UsersStatus = "idle" | "loading" | "success" | "error";

function isValidUsersListResponse(data: unknown): data is UsersListResponse {
  if (data === null || typeof data !== "object") return false;
  const o = data as Record<string, unknown>;
  if (!Array.isArray(o.users)) return false;
  for (const u of o.users) {
    if (typeof u !== "object" || u === null) return false;
    const user = u as Record<string, unknown>;
    if (typeof user.id !== "number" || typeof user.username !== "string" || typeof user.role !== "string")
      return false;
  }
  return true;
}

export default function AdminUsersPage() {
  const [status, setStatus] = useState<UsersStatus>("idle");
  const [data, setData] = useState<UsersListResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchUsers = useCallback(async () => {
    const baseUrl = getApiBaseUrl();
    setStatus("loading");
    setErrorMessage(null);
    setData(null);
    try {
      const res = await fetch(`${baseUrl}/api/v1/auth/users`, {
        headers: getAuthHeaders(),
      });
      const body: unknown = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (res.status === 401) {
          setErrorMessage("Unauthorized. Log in or paste a valid token.");
        } else if (res.status === 403) {
          setErrorMessage("Forbidden. Admin role required.");
        } else {
          const detail =
            body !== null && typeof body === "object" && "detail" in body
              ? String((body as { detail?: unknown }).detail)
              : res.statusText;
          setErrorMessage(detail);
        }
        setStatus("error");
        return;
      }
      if (!isValidUsersListResponse(body)) {
        setErrorMessage("Invalid users response shape.");
        setStatus("error");
        return;
      }
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
      {status === "error" && (
        <div role="alert" style={{ marginBottom: "1rem", color: "#b91c1c" }}>
          <p>{errorMessage}</p>
          <button type="button" onClick={fetchUsers} aria-label="Retry load users">
            Retry
          </button>
        </div>
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
