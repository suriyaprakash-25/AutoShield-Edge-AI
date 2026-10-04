import { getEcuName } from "../data/loadCanData";

export default function TrafficFeed({ frames }) {
  return (
    <div
      style={{
        background: "var(--bg-panel)",
        border: "1px solid var(--line)",
        borderRadius: "var(--radius)",
        overflow: "hidden",
        display: "flex",
        flexDirection: "column",
        height: "100%",
      }}
    >
      <div
        style={{
          padding: "10px 14px",
          borderBottom: "1px solid var(--line)",
          fontSize: 11,
          fontWeight: 600,
          color: "var(--text-secondary)",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
        }}
      >
        Live CAN traffic
      </div>
      <div style={{ flex: 1, overflowY: "auto", padding: "4px 0" }}>
        {frames.length === 0 && (
          <div style={{ padding: 20, color: "var(--text-tertiary)", fontSize: 12, textAlign: "center" }}>
            No traffic yet — press play
          </div>
        )}
        {frames.map((f, i) => (
          <div
            key={i}
            className="mono"
            style={{
              display: "grid",
              gridTemplateColumns: "70px 56px 1fr 110px",
              gap: 8,
              padding: "4px 14px",
              fontSize: 11,
              color: f.flag === "T" ? "var(--signal-red)" : "var(--text-secondary)",
              background: f.flag === "T" ? "var(--signal-red-dim)" : "transparent",
              alignItems: "center",
            }}
          >
            <span style={{ opacity: 0.7 }}>{f.timestamp.toFixed(3)}s</span>
            <span style={{ fontWeight: 600 }}>0x{f.canId}</span>
            <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {f.dataBytes.join(" ")}
            </span>
            <span style={{ fontSize: 10, textAlign: "right", color: "var(--text-tertiary)" }}>{getEcuName(f.canId)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
