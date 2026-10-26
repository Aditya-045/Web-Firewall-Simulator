import React from "react";
import { t } from "../translations.js";

const VERDICT_STYLES = {
  malicious: "text-malicious",
  safe: "text-safe",
  unknown: "text-unknown",
};

export default function HistoryList({ items, language = "en" }) {
  if (!items || items.length === 0) {
    return <p className="text-xs text-inkfaint">{t(language, "noScansYet")}</p>;
  }

  return (
    <ul className="flex flex-col divide-y divide-line border border-line rounded-md overflow-hidden bg-white shadow-sm">
      {items.map((item) => (
        <li key={item.scan_id} className="px-3 py-2.5 flex items-center justify-between gap-3 hover:bg-base/60 transition-colors">
          <div className="min-w-0">
            <p className="text-xs font-mono truncate">{item.input_value}</p>
            <p className="text-[11px] text-inkfaint">
              {item.content_type === "url" ? t(language, "link") : t(language, "textMessage")}
              {" "}&middot;{" "}
              {item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : ""}
            </p>
          </div>
          <span
            className={`text-[11px] font-medium uppercase shrink-0 ${VERDICT_STYLES[item.verdict] || "text-unknown"}`}
          >
            {t(language, item.verdict === "malicious" ? "malicious" : item.verdict === "safe" ? "safe" : "unknown")}
          </span>
        </li>
      ))}
    </ul>
  );
}
