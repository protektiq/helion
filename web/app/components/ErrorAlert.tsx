"use client";

type ErrorAlertProps = {
  message: string;
  onRetry?: () => void;
  retryLabel?: string;
};

const ERROR_ALERT_STYLE: React.CSSProperties = {
  marginBottom: "1rem",
  color: "#b91c1c",
};

export default function ErrorAlert({
  message,
  onRetry,
  retryLabel,
}: ErrorAlertProps) {
  return (
    <div role="alert" style={ERROR_ALERT_STYLE}>
      <p style={{ margin: 0 }}>{message}</p>
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
