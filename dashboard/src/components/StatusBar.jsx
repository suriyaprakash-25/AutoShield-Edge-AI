const SCENARIO_LABELS = {
  normal: "Normal traffic",
  dos: "DoS attack",
  fuzzy: "Fuzzy attack",
  rpm: "RPM spoof",
  gear: "Gear spoof",
};

export default function StatusBar({ scenario, isPlaying, frameIdx, latencyMs, backendOnline, connectionText, model }) {
  const underAttack = scenario !== "normal";
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "14px 24px", background: "var(--bg-panel)", borderBottom: "1px solid var(--line)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ width: 9, height: 9, borderRadius: "50%", background: backendOnline ? "var(--signal-green)" : "var(--signal-amber)", animation: isPlaying ? "blink 1.4s infinite" : "none" }} />
        <span style={{ fontWeight: 600, fontSize: 14 }}>AutoShield Edge AI</span>
        <span style={{ color: "var(--text-tertiary)", fontSize: 12 }}>{model || "Hybrid-v4"}</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 26 }}>
        <Metric label="backend" value={connectionText} accent={backendOnline ? "var(--signal-green)" : "var(--signal-amber)"} mono />
        <Metric label="scenario" value={SCENARIO_LABELS[scenario] || scenario} accent={underAttack ? "var(--signal-amber)" : "var(--signal-cyan)"} />
        <Metric label="100 ms windows" value={frameIdx.toLocaleString()} mono />
        <Metric label="inference" value={`${Number(latencyMs).toFixed(2)} ms`} mono accent="var(--signal-cyan)" />
      </div>
    </div>
  );
}

function Metric({ label, value, accent, mono }) {
  return (
    <div style={{ textAlign: "right" }}>
      <div style={{ fontSize: 10, color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</div>
      <div className={mono ? "mono" : ""} style={{ fontSize: 12, fontWeight: 600, color: accent || "var(--text-primary)" }}>{value}</div>
    </div>
  );
}
