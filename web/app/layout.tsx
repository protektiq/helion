import type { Metadata } from "next";
import Link from "next/link";
import AuthTokenInput from "./components/AuthTokenInput";
import EnvironmentBadge from "./components/EnvironmentBadge";

export const metadata: Metadata = {
  title: "Helion",
  description: "Vulnerability findings upload, clusters, reasoning, and Jira export",
};

const navLinkStyle = {
  color: "#2563eb",
  textDecoration: "underline" as const,
  marginRight: "1rem",
  fontSize: "0.875rem",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </head>
      <body>
        <header
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "0.5rem 1rem",
            borderBottom: "1px solid #e5e7eb",
            backgroundColor: "#f9fafb",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "1rem", flexWrap: "wrap" }}>
            <Link href="/" style={{ fontSize: "1rem", fontWeight: 600, color: "inherit", textDecoration: "none" }} aria-label="Helion home">Helion</Link>
            <nav aria-label="Main" style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: "0.25rem" }}>
              <Link href="/upload" style={navLinkStyle} aria-label="Upload">Upload</Link>
              <Link href="/results" style={navLinkStyle} aria-label="Results">Results</Link>
              <Link href="/reasoning" style={navLinkStyle} aria-label="Reasoning">Reasoning</Link>
              <Link href="/exploitability" style={navLinkStyle} aria-label="Exploitability">Exploitability</Link>
              <Link href="/tickets" style={navLinkStyle} aria-label="Tickets preview">Tickets</Link>
              <Link href="/jira" style={navLinkStyle} aria-label="Jira export">Jira Export</Link>
              <Link href="/admin/users" style={navLinkStyle} aria-label="Admin users">Admin Users</Link>
            </nav>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "1rem", flexShrink: 0 }}>
            <EnvironmentBadge />
            <AuthTokenInput />
          </div>
        </header>
        {children}
      </body>
    </html>
  );
}
