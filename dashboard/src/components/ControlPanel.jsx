import { SCENARIOS } from "../data/loadCanData";

export default function ControlPanel({ scenario, onScenarioChange, isPlaying, onTogglePlay, onReset, loading }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 16, padding: "12px 24px", background: "var(--bg-panel-raised)", borderBottom: "1px solid var(--line)" }}>
      <span style={{ fontSize: 11, color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
        Demonstration simulator
      </span>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {Object.entries(SCENARIOS).map(([key, item]) => {
          const isMix = key === "mix";
          const activeColor = isMix ? "var(--signal-purple)" : "var(--signal-cyan)";
          const activeBg = isMix ? "var(--signal-purple-dim)" : "var(--signal-cyan-dim)";
          return (
          <button
            key={key}
            data-testid={`scenario-${key}`}
            onClick={() => onScenarioChange(key)}
            disabled={loading}
            title={item.description}
            style={{
              padding: "6px 12px",
              fontSize: 12,
              fontWeight: 600,
              borderRadius: "var(--radius)",
              border: `1px solid ${scenario === key ? activeColor : (isMix ? "rgba(192,132,252,0.45)" : "var(--line-strong)")}`,
              background: scenario === key ? activeBg : "transparent",
              color: scenario === key ? activeColor : (isMix ? "var(--signal-purple)" : "var(--text-secondary)"),
              cursor: loading ? "default" : "pointer",
              opacity: loading ? 0.5 : 1,
            }}
          >
            {item.label}
          </button>
          );
        })}
      </div>
      <div style={{ flex: 1 }} />
      <button
        data-testid="start-stop"
        onClick={onTogglePlay}
        disabled={loading}
        style={{ padding: "6px 18px", fontSize: 12, fontWeight: 600, borderRadius: "var(--radius)", border: "1px solid var(--signal-cyan)", background: isPlaying ? "transparent" : "var(--signal-cyan-dim)", color: "var(--signal-cyan)", cursor: loading ? "default" : "pointer" }}
      >
        {isPlaying ? "Stop" : "Start"}
      </button>
      <button
        data-testid="reset"
        onClick={onReset}
        disabled={loading}
        style={{ padding: "6px 14px", fontSize: 12, fontWeight: 600, borderRadius: "var(--radius)", border: "1px solid var(--line-strong)", background: "transparent", color: "var(--text-secondary)", cursor: loading ? "default" : "pointer" }}
      >
        Reset
      </button>
      <span className="mono" style={{ fontSize: 10, color: "var(--text-tertiary)" }}>
        100 ms windows · repeatable seed
      </span>
    </div>
  );
}
