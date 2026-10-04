function packetStyle(status) {
  if (status === "isolated") return { fill: "var(--signal-red)", glow: "rgba(255,77,94,0.95)" };
  if (status === "suspicious" || status === "collateral") {
    return { fill: "var(--signal-amber)", glow: "rgba(255,178,56,0.95)" };
  }
  return { fill: "var(--signal-cyan)", glow: "rgba(79,209,232,0.95)" };
}

function scenarioDuration(scenario, status, index) {
  if (status !== "normal") return 0.72 + (index % 3) * 0.08;
  if (scenario === "mix") return 0.62 + (index % 3) * 0.05;
  if (scenario === "dos") return 0.95 + (index % 3) * 0.08;
  if (scenario === "fuzzy") return 1.25 + (index % 4) * 0.09;
  return 1.85 + (index % 4) * 0.16;
}

export default function CanTrafficOverlay({
  width,
  height,
  cx,
  cy,
  ecuIds,
  positions,
  networkState,
  scenario,
  isPlaying,
}) {
  const globalAlert = scenario === "dos" || scenario === "fuzzy" || scenario === "mix";
  return (
    <svg
      data-testid="can-activity-layer"
      viewBox={`0 0 ${width} ${height}`}
      aria-label={isPlaying ? "Live CAN message flow" : "CAN bus paused"}
      style={{
        position: "absolute",
        inset: 0,
        width: "100%",
        height: "100%",
        pointerEvents: "none",
        overflow: "visible",
      }}
    >
      <circle
        cx={cx}
        cy={cy}
        r={38}
        fill="none"
        stroke={globalAlert ? "var(--signal-amber)" : "var(--signal-cyan)"}
        strokeWidth={1.2}
        opacity={isPlaying ? 0.42 : 0.12}
      >
        {isPlaying && (
          <>
            <animate attributeName="r" values="38;54;38" dur={globalAlert ? "0.85s" : "1.8s"} repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.5;0.08;0.5" dur={globalAlert ? "0.85s" : "1.8s"} repeatCount="indefinite" />
          </>
        )}
      </circle>
      {isPlaying && ecuIds.flatMap((id, index) => {
        const pos = positions[id];
        const status = networkState[id] || "normal";
        const style = packetStyle(status);
        const duration = scenarioDuration(scenario, status, index);
        const count = scenario === "mix" ? 3 : (scenario === "dos" || status !== "normal" ? 2 : 1);

        return Array.from({ length: count }, (_, copy) => {
          const outbound = (index + copy) % 2 === 0;
          const path = outbound
            ? `M ${pos.x} ${pos.y} L ${cx} ${cy}`
            : `M ${cx} ${cy} L ${pos.x} ${pos.y}`;
          const begin = ((index * 0.13) + (copy * 0.31)).toFixed(2);

          return (
            <circle
              key={`${id}-${copy}`}
              className="can-packet-dot"
              data-can-id={id}
              r={status === "normal" ? 3.2 : 4.2}
              fill={style.fill}
              style={{ filter: `drop-shadow(0 0 5px ${style.glow})` }}
            >
              <animateMotion
                path={path}
                dur={`${duration}s`}
                begin={`${begin}s`}
                repeatCount="indefinite"
              />
              <animate
                attributeName="opacity"
                values="0;1;1;0"
                dur={`${duration}s`}
                begin={`${begin}s`}
                repeatCount="indefinite"
              />
            </circle>
          );
        });
      })}
      <g transform={`translate(${cx - 90}, ${height - 12})`}>
        <circle
          r={3.2}
          fill={isPlaying ? "var(--signal-green)" : "var(--text-tertiary)"}
          opacity={isPlaying ? 1 : 0.55}
        >
          {isPlaying && (
            <animate attributeName="opacity" values="1;0.35;1" dur="1.1s" repeatCount="indefinite" />
          )}
        </circle>
        <text
          x={10}
          y={3}
          fill={isPlaying ? "var(--signal-green)" : "var(--text-tertiary)"}
          fontFamily="var(--font-mono)"
          fontSize="9"
          fontWeight="700"
          letterSpacing="0.12em"
        >
          {isPlaying ? "LIVE CAN MESSAGE FLOW" : "CAN BUS PAUSED"}
        </text>
      </g>
    </svg>
  );
}
