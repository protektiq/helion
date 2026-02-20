import type { Metadata } from "next";
import Link from "next/link";
import AuthTokenInput from "./components/AuthTokenInput";

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
            <span style={{ fontSize: "1rem", fontWeight: 600 }}>Helion</span>
            <nav aria-label="Main" style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: "0.25rem" }}>
              <Link href="/" style={navLinkStyle} aria-label="Home">Home</Link>
              <Link href="/health" style={navLinkStyle} aria-label="Health">Health</Link>
              <Link href="/login" style={navLinkStyle} aria-label="Login">Login</Link>
              <Link href="/upload" style={navLinkStyle} aria-label="Upload">Upload</Link>
              <Link href="/results" style={navLinkStyle} aria-label="Results">Results</Link>
              <Link href="/reasoning" style={navLinkStyle} aria-label="Reasoning">Reasoning</Link>
              <Link href="/exploitability" style={navLinkStyle} aria-label="Exploitability">Exploitability</Link>
              <Link href="/tickets" style={navLinkStyle} aria-label="Tickets preview">Tickets</Link>
              <Link href="/jira-export" style={navLinkStyle} aria-label="Jira export">Jira Export</Link>
              <Link href="/admin/users" style={navLinkStyle} aria-label="Admin users">Admin Users</Link>
            </nav>
          </div>
          <AuthTokenInput />
        </header>
        {children}
      </body>
    </html>
  );
}
