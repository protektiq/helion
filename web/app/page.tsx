"use client";

import Link from "next/link";

export default function HomePage() {
  return (
    <main style={{ padding: "2rem", maxWidth: "40rem", margin: "0 auto" }}>
      <h1 style={{ fontSize: "1.25rem", marginBottom: "0.5rem" }}>Helion</h1>
      <p style={{ color: "#374151", marginBottom: "1.5rem", fontSize: "0.9375rem" }}>
        Upload SAST/SCA findings, view clusters, run reasoning and exploitability, preview tickets, and export to Jira. Use the links above to navigate.
      </p>
      <nav aria-label="Quick links" style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem 1rem" }}>
        <Link href="/health" style={{ color: "#2563eb", textDecoration: "underline" }}>Health</Link>
        <Link href="/login" style={{ color: "#2563eb", textDecoration: "underline" }}>Login</Link>
        <Link href="/upload" style={{ color: "#2563eb", textDecoration: "underline" }}>Upload</Link>
        <Link href="/results" style={{ color: "#2563eb", textDecoration: "underline" }}>Results</Link>
        <Link href="/reasoning" style={{ color: "#2563eb", textDecoration: "underline" }}>Reasoning</Link>
        <Link href="/exploitability" style={{ color: "#2563eb", textDecoration: "underline" }}>Exploitability</Link>
        <Link href="/tickets" style={{ color: "#2563eb", textDecoration: "underline" }}>Tickets</Link>
        <Link href="/jira-export" style={{ color: "#2563eb", textDecoration: "underline" }}>Jira Export</Link>
        <Link href="/admin/users" style={{ color: "#2563eb", textDecoration: "underline" }}>Admin Users</Link>
      </nav>
    </main>
  );
}
