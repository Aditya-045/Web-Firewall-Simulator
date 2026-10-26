import React from "react";
import { t } from "../translations.js";

const ZONE_META = [
  { key: "safe", from: 0, to: 40, color: "#2F7A4D" },
  { key: "unknown", from: 40, to: 60, color: "#F4F4F5", stroke: "#C7CAD1" },
  { key: "malicious", from: 60, to: 100, color: "#B23A2F" },
];

export default function ConfidenceGauge({ confidencePct, verdict, language = "en" }) {
  const clamped = Math.min(Math.max(confidencePct, 0), 100);
  const verdictColor =
    verdict === "malicious" ? "#B23A2F" : verdict === "safe" ? "#2F7A4D" : "#6B7280";

  return (
    <div className="w-full">
      <div className="flex items-baseline justify-between mb-2">
        <span className="font-mono text-xs tracking-wide text-inkfaint uppercase">
          {t(language, "confidence")}
        </span>
        <span
          className="font-mono text-3xl font-semibold tabular-nums transition-colors duration-300"
          style={{ color: verdictColor }}
        >
          {clamped.toFixed(1)}%
        </span>
      </div>

      <svg viewBox="0 0 400 46" className="w-full h-auto drop-shadow-sm">
        {ZONE_META.map((z) => (
          <rect
            key={z.key}
            x={z.from * 4}
            y={10}
            width={(z.to - z.from) * 4}
            height={16}
            rx={2}
            fill={z.color}
            stroke={z.stroke || "none"}
            strokeWidth={z.stroke ? 1 : 0}
            opacity={0.95}
          />
        ))}
        {/* zone divider ticks */}
        {[40, 60].map((tick) => (
          <line key={tick} x1={tick * 4} y1={6} x2={tick * 4} y2={30} stroke="#14181F" strokeOpacity={0.2} strokeWidth={1} />
        ))}
        {/* needle marker at exact confidence, animated via CSS transition on transform */}
        <g style={{ transition: "transform 0.5s cubic-bezier(0.34, 1.56, 0.64, 1)" }} transform={`translate(${clamped * 4}, 0)`}>
          <polygon points="0,0 -6,-8 6,-8" fill="#14181F" />
          <line x1={0} y1={0} x2={0} y2={34} stroke="#14181F" strokeWidth={2} />
        </g>
      </svg>

      <div className="flex justify-between mt-1 font-mono text-[11px] text-inkfaint">
        <span>0%</span>
        <span>40%</span>
        <span>60%</span>
        <span>100%</span>
      </div>

      <div className="flex gap-4 mt-3">
        {ZONE_META.map((z) => (
          <div key={z.key} className="flex items-center gap-1.5">
            <span
              className="inline-block w-2.5 h-2.5 rounded-sm"
              style={{ backgroundColor: z.color, border: z.stroke ? `1px solid ${z.stroke}` : "none" }}
            />
            <span className="text-xs text-inkfaint">{t(language, z.key)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
