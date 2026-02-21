"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { getToken } from "@/lib/auth";
import {
  getHasSeen401,
  subscribeTo401,
} from "@/lib/authBanner";

const BANNER_STYLE: React.CSSProperties = {
  padding: "0.5rem 1rem",
  backgroundColor: "#fef3c7",
  borderBottom: "1px solid #f59e0b",
  fontSize: "0.875rem",
  color: "#92400e",
  display: "flex",
  alignItems: "center",
  gap: "0.5rem",
  flexWrap: "wrap",
};

const LINK_STYLE: React.CSSProperties = {
  color: "#b45309",
  fontWeight: 600,
  textDecoration: "underline",
};

function getShowBanner(): boolean {
  const seen = getHasSeen401();
  const token = getToken();
  return seen && (typeof token !== "string" || token.trim().length === 0);
}

export default function AuthRequiredBanner() {
  const [showBanner, setShowBanner] = useState(false);

  const updateBanner = useCallback(() => {
    setShowBanner(getShowBanner());
  }, []);

  useEffect(() => {
    updateBanner();
    const unsubscribe = subscribeTo401(updateBanner);
    return unsubscribe;
  }, [updateBanner]);

  if (!showBanner) {
    return null;
  }

  return (
    <div
      role="alert"
      aria-live="polite"
      style={BANNER_STYLE}
    >
      <span>
        Auth required. Go to{" "}
        <Link
          href="/login"
          style={LINK_STYLE}
          aria-label="Go to login to get a token"
        >
          /login
        </Link>{" "}
        to get a token.
      </span>
    </div>
  );
}
