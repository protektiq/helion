import type { Metadata } from "next";
import AuthTokenInput from "./components/AuthTokenInput";

export const metadata: Metadata = {
  title: "Helion Upload",
  description: "Upload SAST/SCA findings JSON",
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
          <span style={{ fontSize: "1rem", fontWeight: 600 }}>Helion</span>
          <AuthTokenInput />
        </header>
        {children}
      </body>
    </html>
  );
}
