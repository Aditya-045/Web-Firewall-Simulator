import React from "react";

export default function VerdictIcon({ verdict, className = "w-5 h-5" }) {
  if (verdict === "malicious") {
    return (
      <svg viewBox="0 0 24 24" fill="none" className={className}>
        <path
          d="M12 3 2 20h20L12 3Z"
          stroke="currentColor"
          strokeWidth={1.8}
          strokeLinejoin="round"
        />
        <line x1="12" y1="10" x2="12" y2="14" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" />
        <circle cx="12" cy="17" r="1" fill="currentColor" />
      </svg>
    );
  }
  if (verdict === "safe") {
    return (
      <svg viewBox="0 0 24 24" fill="none" className={className}>
        <circle cx="12" cy="12" r="9.2" stroke="currentColor" strokeWidth={1.8} />
        <path d="M8 12.5l2.6 2.6L16.5 9" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  // unknown / not sure
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className}>
      <circle cx="12" cy="12" r="9.2" stroke="currentColor" strokeWidth={1.8} strokeDasharray="3 3" />
      <path
        d="M9.6 9.3a2.4 2.4 0 1 1 3.4 2.2c-.7.4-1 .8-1 1.6"
        stroke="currentColor"
        strokeWidth={1.8}
        strokeLinecap="round"
      />
      <circle cx="12" cy="16.3" r="0.9" fill="currentColor" />
    </svg>
  );
}
