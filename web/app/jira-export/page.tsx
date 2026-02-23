"use client";

import { useState, useCallback, useEffect } from "react";
import { createApiClient, getErrorMessage, getValidationDetail } from "@/lib/apiClient";
import { getSelectedJobId, setSelectedJobId } from "@/lib/jobStorage";
import type {
  JiraExportResponse,
  UploadJobListItem,
  ValidationError,
} from "@/lib/types";
import ErrorAlert from "@/app/components/ErrorAlert";

type JiraExportStatus = "idle" | "submitting" | "success" | "error";

export default function JiraExportPage() {
  const [useDb, setUseDb] = useState(true);
  const [jobId, setJobId] = useState<number | null>(null);
  const [jobs, setJobs] = useState<UploadJobListItem[]>([]);
  const [useReasoning, setUseReasoning] = useState(false);
  const [status, setStatus] = useState<JiraExportStatus>("idle");
  const [response, setResponse] = useState<JiraExportResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorDetail, setErrorDetail] = useState<ValidationError[] | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const client = createApiClient();
        const res = await client.listUploadJobs();
        setJobs(res.jobs ?? []);
      } catch {
        setJobs([]);
      }
    };
    load();
  }, []);

  useEffect(() => {
    if (jobs.length === 0) return;
    if (jobs.length === 1) {
      setJobId(jobs[0].id);
      setSelectedJobId(jobs[0].id);
      return;
    }
    const stored = getSelectedJobId();
    const inList = stored !== null && jobs.some((j) => j.id === stored);
    const next = inList ? stored! : jobs[0].id;
    setJobId(next);
    setSelectedJobId(next);
  }, [jobs]);

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
      setErrorDetail(null);
      try {
        const client = createApiClient();
        const data = await client.postJiraExport({
          clusters: [],
          use_db: useDb,
          use_reasoning: useReasoning,
          ...(useDb && jobId != null ? { job_id: jobId } : {}),
        });
        setResponse(data);
        setStatus("success");
      } catch (err) {
        setErrorMessage(getErrorMessage(err));
        setErrorDetail(getValidationDetail(err));
        setStatus("error");
      }
    },
    [useDb, jobId, useReasoning]
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
        {useDb && jobs.length > 0 && (
          <label
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              marginBottom: "0.75rem",
            }}
          >
            <span style={{ whiteSpace: "nowrap" }}>Upload job</span>
            <select
              value={jobId ?? ""}
              onChange={(e) => {
                const v = e.target.value;
                const id = v === "" ? null : parseInt(v, 10) || null;
                if (id !== null) {
                  setJobId(id);
                  setSelectedJobId(id);
                }
              }}
              aria-label="Select upload job for export"
              style={{ minWidth: "12rem" }}
            >
              {jobs.map((j) => (
                <option key={j.id} value={j.id}>
                  Job {j.id} ({j.finding_count} findings)
                </option>
              ))}
            </select>
          </label>
        )}
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
      {status === "error" && errorMessage !== null && errorMessage !== "" && (
        <ErrorAlert message={errorMessage} detail={errorDetail} />
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
