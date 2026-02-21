"use client";

import type { ValidationError } from "@/lib/types";

type ErrorAlertProps = {
  message: string;
  /** Optional validation detail (422): string or list of field errors to show below message. */
  detail?: string | ValidationError[] | null;
  onRetry?: () => void;
  retryLabel?: string;
};

const ERROR_ALERT_STYLE: React.CSSProperties = {
  marginBottom: "1rem",
  color: "#b91c1c",
};

const DETAIL_STYLE: React.CSSProperties = {
  marginTop: "0.5rem",
  fontSize: "0.875rem",
};

function formatValidationItem(d: ValidationError): string {
  const loc = Array.isArray(d.loc) ? d.loc.join(".") : "";
  return loc ? `${loc}: ${d.msg}` : d.msg;
}

export default function ErrorAlert({
  message,
  detail,
  onRetry,
  retryLabel,
}: ErrorAlertProps) {
  const hasDetail =
    typeof detail === "string"
      ? detail.length > 0
      : Array.isArray(detail) && detail.length > 0;

  return (
    <div role="alert" style={ERROR_ALERT_STYLE}>
      <p style={{ margin: 0 }}>{message}</p>
      {hasDetail && (
        <div style={DETAIL_STYLE}>
          {typeof detail === "string" ? (
            <p style={{ margin: 0 }}>{detail}</p>
          ) : (
            <ul style={{ margin: 0, paddingLeft: "1.25rem" }}>
              {detail!.map((d, i) => (
                <li key={i}>{formatValidationItem(d)}</li>
              ))}
            </ul>
          )}
        </div>
      )}
      {typeof onRetry === "function" && (
        <button
          type="button"
          onClick={onRetry}
          aria-label={retryLabel ?? "Retry"}
          style={{ marginTop: "0.5rem" }}
        >
          Retry
        </button>
      )}
    </div>
  );
}
