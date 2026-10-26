import React from "react";

export default function PipelineDiagram() {
  const steps = [
    { label: "Input", desc: "Link or text" },
    { label: "ML model", desc: "Trained classifier" },
    { label: "Heuristics", desc: "Low-confidence cases only" },
    { label: "Verdict", desc: "Safe / Uncertain / Malicious" },
  ];

  return (
    <div className="flex flex-col items-center justify-center h-full py-16 gap-8">
      <svg viewBox="0 0 520 90" className="w-full max-w-md">
        {steps.map((s, i) => {
          const x = 20 + i * 170;
          return (
            <g key={s.label}>
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
        Submit a link or a message on the left. Results will appear here, along
        with the confidence readout and, for links, the resolved source details.
      </p>
    </div>
  );
}
