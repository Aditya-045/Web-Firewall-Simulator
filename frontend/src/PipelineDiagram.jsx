import React from "react";
import { t } from "../translations.js";

export default function PipelineDiagram({ language = "en" }) {
  const steps = [
    { label: t(language, "pipelineInput"), desc: t(language, "pipelineInputDesc") },
    { label: t(language, "pipelineMlModel"), desc: t(language, "pipelineMlModelDesc") },
    { label: t(language, "pipelineHeuristics"), desc: t(language, "pipelineHeuristicsDesc") },
    { label: t(language, "pipelineVerdict"), desc: t(language, "pipelineVerdictDesc") },
  ];

  return (
    <div className="flex flex-col items-center justify-center h-full py-16 gap-8">
      <svg viewBox="0 0 520 90" className="w-full max-w-md">
        {steps.map((s, i) => {
          const x = 20 + i * 170;
          return (
            <g key={i}>
              <rect x={x} y={10} width={130} height={50} fill="none" stroke="#D8DCE3" strokeWidth={1.5} />
              <text x={x + 65} y={32} textAnchor="middle" className="fill-ink" style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: 13, fontWeight: 600 }}>
                {s.label}
              </text>
              <text x={x + 65} y={48} textAnchor="middle" style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 9, fill: "#5C6270" }}>
                {s.desc}
              </text>
              {i < steps.length - 1 && (
                <line x1={x + 130} y1={35} x2={x + 170} y2={35} stroke="#8A8F98" strokeWidth={1.5} />
              )}
            </g>
          );
        })}
      </svg>
      <p className="text-sm text-inkfaint max-w-sm text-center">
        {t(language, "pipelineExplain")}
      </p>
    </div>
  );
}
