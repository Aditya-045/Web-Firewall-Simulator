import React, { useState, useCallback, useEffect } from "react";
import ScanForm from "./components/ScanForm.jsx";
import ConfidenceGauge from "./components/ConfidenceGauge.jsx";
import MetadataPanel from "./components/MetadataPanel.jsx";
import FeedbackButtons from "./components/FeedbackButtons.jsx";
import HistoryList from "./components/HistoryList.jsx";
import PipelineDiagram from "./components/PipelineDiagram.jsx";
import LanguageSelect from "./components/LanguageSelect.jsx";
import VerdictIcon from "./components/VerdictIcon.jsx";
import { t } from "./translations.js";

export default function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [language, setLanguage] = useState("en");

  const loadHistory = useCallback(async () => {
    try {
      const res = await fetch("/api/history?limit=15");
      if (res.ok) setHistory(await res.json());
    } catch {
      /* history is a nice-to-have; ignore failures silently */
    }
  }, []);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  async function handleScan(mode, value) {
    setLoading(true);
    setError(null);
    try {
      const endpoint = mode === "url" ? "/api/scan/url" : "/api/scan/text";
      const body = mode === "url" ? { url: value } : { text: value };
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        // The backend now returns { detail: "ExceptionType: message" } on
        // errors (see main.py's global exception handler) instead of a
        // bare status code, so surface that real reason here.
        let detail = `Server returned ${res.status}`;
        try {
          const errBody = await res.json();
          if (errBody?.detail) detail = errBody.detail;
        } catch {
          /* body wasn't JSON, fall back to the generic message above */
        }
        throw new Error(detail);
      }

      const data = await res.json();
      setResult(data);
      loadHistory();
    } catch (e) {
      setError(
        e.message.includes("Failed to fetch")
          ? "Could not reach the backend. Is the FastAPI server running on port 8000?"
          : e.message
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleFeedback(scanId, label) {
    await fetch("/api/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: scanId, confirmed_label: label }),
    });
    loadHistory();
  }

  const verdictBadgeStyle =
    result?.verdict === "malicious"
      ? "bg-maliciousBg text-malicious"
      : result?.verdict === "safe"
      ? "bg-safeBg text-safe"
      : "bg-unknownBg text-inkfaint border border-line";

  return (
    <div className="min-h-screen bg-gradient-to-b from-base to-[#E4E7EC]">
      <header className="border-b border-line bg-panel/90 backdrop-blur supports-[backdrop-filter]:bg-panel/70 sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-6 py-5 flex items-center justify-between gap-4 flex-wrap">
          <div>
            <h1 className="font-display text-xl font-semibold tracking-tight">
              Threat Scanner
            </h1>
            <p className="text-sm text-inkfaint mt-0.5">
              Check a link or message for malicious intent using a trained model, with source lookup and a live feedback loop.
            </p>
          </div>
          <LanguageSelect language={language} onChange={setLanguage} />
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8 grid grid-cols-1 lg:grid-cols-5 gap-6">
        <section className="lg:col-span-2 flex flex-col gap-6">
          <div className="border border-line bg-panel rounded-lg shadow-sm p-5">
            <ScanForm onScan={handleScan} loading={loading} />
            {error && (
              <div className="mt-3 px-3 py-2.5 bg-maliciousBg border border-malicious/30 rounded-md">
                <p className="text-xs text-malicious font-mono break-words">{error}</p>
                <p className="text-[11px] text-malicious/80 mt-1">
                  Full details are also logged in your backend terminal — check there for the complete traceback.
                </p>
              </div>
            )}
          </div>

          <div>
            <h2 className="font-display text-sm font-medium mb-2 text-inkfaint">
              Recent scans
            </h2>
            <HistoryList items={history} />
          </div>
        </section>

        <section className="lg:col-span-3 border border-line bg-panel rounded-lg shadow-sm p-6 min-h-[420px]">
          {!result ? (
            <PipelineDiagram />
          ) : (
            <div className="flex flex-col gap-6 animate-[fadeIn_0.3s_ease-out]">
              <div>
                <span
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold uppercase tracking-wide mb-3 ${verdictBadgeStyle}`}
                >
                  <VerdictIcon verdict={result.verdict} className="w-3.5 h-3.5" />
                  {t(language, result.verdict === "malicious" ? "malicious" : result.verdict === "safe" ? "safe" : "unknown")}
                </span>
                <p className="font-mono text-sm break-all text-inkfaint">
                  {result.input_value}
                </p>
              </div>

              <ConfidenceGauge
                confidencePct={result.final_confidence * 100}
                verdict={result.verdict}
              />

              <div className="text-xs text-inkfaint">
                Detection path:{" "}
                <span className="font-mono text-ink">{result.detection_path}</span>
                {" · "}
                Raw model confidence:{" "}
                <span className="font-mono text-ink">
                  {(result.ml_confidence * 100).toFixed(1)}%
                </span>
              </div>

              {result.heuristic_reasons?.length > 0 && (
                <div className="border border-line rounded-md p-3 bg-base">
                  <p className="text-xs font-medium mb-1.5">
                    Heuristic layer flagged:
                  </p>
                  <ul className="list-disc list-inside text-xs text-inkfaint space-y-0.5">
                    {result.heuristic_reasons.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </div>
              )}

              {result.source_metadata && (
                <MetadataPanel metadata={result.source_metadata} />
              )}

              <FeedbackButtons
                scanId={result.scan_id}
                onSubmitFeedback={handleFeedback}
                language={language}
              />
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
