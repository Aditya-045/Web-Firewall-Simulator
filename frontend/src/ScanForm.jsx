import React, { useState } from "react";
import { t } from "../translations.js";

export default function ScanForm({ onScan, loading, language = "en" }) {
  const [mode, setMode] = useState("url");
  const [value, setValue] = useState("");

  function handleSubmit(e) {
    e.preventDefault();
    if (!value.trim()) return;
    onScan(mode, value.trim());
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <div className="flex border-b border-line">
        {["url", "text"].map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => setMode(m)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-all duration-150 ${
              mode === m
                ? "border-signal text-signal"
                : "border-transparent text-inkfaint hover:text-ink hover:border-line"
            }`}
          >
            {m === "url" ? t(language, "link") : t(language, "textMessage")}
          </button>
        ))}
      </div>

      {mode === "url" ? (
        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="https://example.com/login"
          className="w-full font-mono text-sm px-4 py-3.5 border border-line bg-white rounded-md focus:border-signal focus:ring-2 focus:ring-signal/10 outline-none transition-all"
        />
      ) : (
        <textarea
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={t(language, "textPlaceholder")}
          rows={6}
          className="w-full text-sm px-4 py-3.5 border border-line bg-white rounded-md focus:border-signal focus:ring-2 focus:ring-signal/10 outline-none resize-none transition-all"
        />
      )}

      <button
        type="submit"
        disabled={loading || !value.trim()}
        className="self-start px-6 py-3 bg-signal text-white text-sm font-semibold rounded-md shadow-sm hover:bg-signalDark hover:shadow-md disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-150 flex items-center gap-2"
      >
        {loading && (
          <span className="w-3.5 h-3.5 border-2 border-white/40 border-t-white rounded-full animate-spin" />
        )}
        {loading ? t(language, "scanning") : t(language, "scan")}
      </button>
    </form>
  );
}
