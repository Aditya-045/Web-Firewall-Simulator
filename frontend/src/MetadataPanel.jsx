import React from "react";
import { t } from "../translations.js";

function Row({ label, value }) {
  return (
    <div className="flex justify-between py-1.5 border-b border-line last:border-0">
      <span className="text-xs text-inkfaint">{label}</span>
      <span className="text-xs font-mono text-ink text-right">{value}</span>
    </div>
  );
}

export default function MetadataPanel({ metadata, language = "en" }) {
  if (!metadata) return null;
  const { dns, whois } = metadata;
  const unavailable = t(language, "unavailable");

  return (
    <div className="border border-line rounded-md bg-white p-4 shadow-sm">
      <h3 className="font-display text-sm font-medium mb-3">{t(language, "sourceDetails")}</h3>
      <Row label={t(language, "resolvedHost")} value={dns?.host ?? unavailable} />
      <Row
        label={t(language, "ipAddress")}
        value={dns?.resolved ? dns.ip_address : t(language, "couldNotResolve")}
      />
      <Row label={t(language, "registrar")} value={whois?.available ? whois.registrar : unavailable} />
      <Row
        label={t(language, "domainCreated")}
        value={whois?.available ? whois.creation_date : unavailable}
      />
      <Row
        label={t(language, "registrantCountry")}
        value={whois?.available ? whois.country : unavailable}
      />
    </div>
  );
}
