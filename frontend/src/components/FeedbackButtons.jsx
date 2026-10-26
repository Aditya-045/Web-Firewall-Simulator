import React, { useState } from "react";
import { t } from "../translations.js";

export default function FeedbackButtons({ scanId, onSubmitFeedback, language = "en" }) {
  const [sent, setSent] = useState(null);

  async function handle(label) {
    await onSubmitFeedback(scanId, label);
    setSent(label);
  }

  if (sent !== null) {
    return (
      <p className="text-xs text-inkfaint font-mono bg-base border border-line rounded-md px-3 py-2">
        {t(language, "thanks")}
      </p>
    );
  }

  return (
    <div className="flex items-center gap-3 flex-wrap">
      <span className="text-xs text-inkfaint">{t(language, "wasCorrect")}</span>
      <button
        onClick={() => handle(1)}
        className="px-3 py-1.5 text-xs font-medium border border-malicious text-malicious rounded-md hover:bg-maliciousBg transition-colors"
      >
        {t(language, "confirmMalicious")}
      </button>
      <button
        onClick={() => handle(0)}
        className="px-3 py-1.5 text-xs font-medium border border-safe text-safe rounded-md hover:bg-safeBg transition-colors"
      >
        {t(language, "confirmSafe")}
      </button>
    </div>
  );
}
