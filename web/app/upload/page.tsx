"use client";

import { useState, useCallback } from "react";
import Link from "next/link";
import { createApiClient, getErrorMessage, getValidationDetail } from "@/lib/apiClient";
import type { UploadResponse, ValidationError } from "@/lib/types";
import ErrorAlert from "@/app/components/ErrorAlert";

type UploadStatus = "idle" | "uploading" | "success" | "error";

export default function UploadPage() {
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<UploadStatus>("idle");
  const [successPayload, setSuccessPayload] = useState<UploadResponse | null>(
    null
  );
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [validationDetails, setValidationDetails] = useState<
    ValidationError[] | null
  >(null);

  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const selected = e.target.files?.[0] ?? null;
      setFile(selected);
      setStatus("idle");
      setSuccessPayload(null);
      setErrorMessage(null);
      setValidationDetails(null);
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

      const formData = new FormData();
      formData.append("file", file);

      setStatus("uploading");
      setSuccessPayload(null);
      setErrorMessage(null);
      setValidationDetails(null);

      try {
        const client = createApiClient();
        const data = await client.uploadFindings(formData);
        setSuccessPayload(data);
        setStatus("success");
      } catch (err) {
        setErrorMessage(getErrorMessage(err));
        setValidationDetails(getValidationDetail(err));
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

      {status === "error" && (errorMessage !== null || (validationDetails !== null && validationDetails.length > 0)) && (
        <ErrorAlert
          message={errorMessage ?? "Validation failed."}
          detail={validationDetails}
        />
      )}
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
          <div>
            <p>
              Done. Accepted: {successPayload.accepted}
              {successPayload.ids && successPayload.ids.length > 0
                ? `. IDs: ${successPayload.ids.length}`
                : ""}
            </p>
            <p style={{ marginTop: "0.5rem" }}>
              <Link
                href="/results"
                style={{ color: "#2563eb", textDecoration: "underline" }}
                aria-label="View results"
              >
                View results
              </Link>
            </p>
          </div>
        )}
      </div>
    </main>
  );
}
