import React from "react";

function Row({ label, value }) {
  return (
    <div className="flex justify-between py-1.5 border-b border-line last:border-0">
      <span className="text-xs text-inkfaint">{label}</span>
      <span className="text-xs font-mono text-ink text-right">{value ?? "unavailable"}</span>
    </div>
  );
}

export default function MetadataPanel({ metadata }) {
  if (!metadata) return null;
  const { dns, whois } = metadata;

  return (
    <div className="border border-line rounded-md bg-white p-4 shadow-sm">
      <h3 className="font-display text-sm font-medium mb-3">Source details</h3>
      <Row label="Resolved host" value={dns?.host} />
      <Row label="IP address" value={dns?.resolved ? dns.ip_address : "could not resolve"} />
      <Row label="Registrar" value={whois?.available ? whois.registrar : "unavailable"} />
      <Row label="Domain created" value={whois?.available ? whois.creation_date : "unavailable"} />
      <Row label="Registrant country" value={whois?.available ? whois.country : "unavailable"} />
    </div>
  );
}
