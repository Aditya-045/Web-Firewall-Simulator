import React from "react";
import { LANGUAGES } from "../translations.js";

export default function LanguageSelect({ language, onChange }) {
  return (
    <div className="flex items-center gap-2">
      <label htmlFor="lang-select" className="text-xs text-inkfaint whitespace-nowrap">
        Result language
      </label>
      <select
        id="lang-select"
        value={language}
        onChange={(e) => onChange(e.target.value)}
        className="text-sm border border-line rounded-md px-2.5 py-1.5 bg-white text-ink focus:border-signal focus:ring-2 focus:ring-signal/10 outline-none transition-all cursor-pointer"
      >
        {LANGUAGES.map((l) => (
          <option key={l.code} value={l.code}>
            {l.label}
          </option>
        ))}
      </select>
    </div>
  );
}
