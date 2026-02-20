"use client";

import { useState, useCallback } from "react";
import { getApiBaseUrl, getAuthHeaders } from "@/lib/api";

type UploadStatus = "idle" | "uploading" | "success" | "error";

type SuccessPayload = {
  accepted: number;
  ids: number[];
};

export default function UploadPage() {
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<UploadStatus>("idle");
  const [successPayload, setSuccessPayload] = useState<SuccessPayload | null>(
    null
  );
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const selected = e.target.files?.[0] ?? null;
      setFile(selected);
      setStatus("idle");
      setSuccessPayload(null);
      setErrorMessage(null);
    },
    []
  );

  const handleSubmit = useCallback(
    async (e: React.FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      if (!file) return;

      const name = file.name.toLowerCase();
      if (!name.endsWith(".json")) {
        setStatus("error");
        setErrorMessage("File must have a .json extension.");
        return;
      }

      const baseUrl = getApiBaseUrl();
      const formData = new FormData();
      formData.append("file", file);

      setStatus("uploading");
      setSuccessPayload(null);
      setErrorMessage(null);

      try {
        const res = await fetch(`${baseUrl}/api/v1/upload`, {
          method: "POST",
          headers: getAuthHeaders(),
          body: formData,
        });

        if (res.ok) {
          const data = (await res.json()) as SuccessPayload;
          setSuccessPayload(data);
          setStatus("success");
          return;
        }

        let detail: string;
        const contentType = res.headers.get("content-type") ?? "";
        if (contentType.includes("application/json")) {
          try {
            const body = (await res.json()) as { detail?: string | string[] };
            if (Array.isArray(body.detail)) {
              detail = body.detail.map((d) => String(d)).join("; ");
            } else if (typeof body.detail === "string") {
              detail = body.detail;
            } else {
              detail = res.statusText || "Upload failed.";
            }
          } catch {
            detail = res.statusText || "Upload failed.";
          }
        } else {
          detail = res.statusText || "Upload failed.";
        }
        setErrorMessage(detail);
        setStatus("error");
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "Network or request failed.";
        setErrorMessage(message);
        setStatus("error");
      }
    },
    [file]
  );

  const isSubmitDisabled = !file || status === "uploading";

  return (
    <main style={{ padding: "2rem", maxWidth: "32rem", margin: "0 auto" }}>
      <h1 style={{ fontSize: "1.25rem", marginBottom: "1rem" }}>
        Upload findings (JSON)
      </h1>
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: "1rem" }}>
          <label htmlFor="file-input" style={{ display: "block", marginBottom: "0.5rem" }}>
            File
          </label>
          <input
            id="file-input"
            type="file"
            accept=".json"
            onChange={handleFileChange}
            aria-label="Select JSON file"
          />
        </div>
        <button
          type="submit"
          disabled={isSubmitDisabled}
          aria-busy={status === "uploading"}
          aria-label={status === "uploading" ? "Uploading" : "Submit"}
        >
          Submit
        </button>
      </form>

      <div
        role="status"
        aria-live="polite"
        style={{ marginTop: "1rem", minHeight: "1.5em" }}
      >
        {status === "idle" && (
          <p style={{ color: "#666" }}>Select a JSON file and submit.</p>
        )}
        {status === "uploading" && <p>Uploading…</p>}
        {status === "success" && successPayload !== null && (
          <p>Done. Accepted: {successPayload.accepted}</p>
        )}
        {status === "error" && errorMessage !== null && (
          <p style={{ color: "#c00" }}>{errorMessage}</p>
        )}
      </div>
    </main>
  );
}
