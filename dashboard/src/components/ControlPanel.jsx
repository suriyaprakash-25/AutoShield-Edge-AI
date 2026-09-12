import { useState } from "react";
import { SCENARIOS } from "../data/loadCanData";

const SCENARIO_ACCENT = {
  normal: { color: "var(--signal-cyan)",   dim: "var(--signal-cyan-dim)",   dot: "#4fd1e8" },
  dos:    { color: "var(--signal-red)",    dim: "var(--signal-red-dim)",    dot: "#ff4d5e" },
  fuzzy:  { color: "var(--signal-amber)",  dim: "var(--signal-amber-dim)",  dot: "#ffb238" },
  spoof:  { color: "var(--signal-purple)", dim: "var(--signal-purple-dim)", dot: "#c084fc" },
};

function ScenarioPill({ scenarioKey, label, selected, onClick, disabled }) {
  const acc = SCENARIO_ACCENT[scenarioKey] || SCENARIO_ACCENT.normal;
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        display: "flex", alignItems: "center", gap: 6,
        padding: "4px 10px", fontSize: 10.5, fontWeight: 600, borderRadius: 20,
        border: `1px solid ${selected ? acc.color : "var(--line-strong)"}`,
        background: selected ? acc.dim : "transparent",
        color: selected ? acc.color : "var(--text-secondary)",
        cursor: disabled ? "default" : "pointer",
        opacity: disabled ? 0.5 : 1,
        transition: "background 0.2s, border-color 0.2s, color 0.2s",
        letterSpacing: "0.02em",
      }}
    >
      <span style={{
        width: 6, height: 6, borderRadius: "50%", flexShrink: 0,
        background: selected ? acc.dot : "var(--text-tertiary)",
        transition: "background 0.2s",
      }} />
      {label}
    </button>
  );
}

function PlayButton({ isPlaying, onClick, disabled }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        display: "flex", alignItems: "center", gap: 7,
        padding: "5px 16px", fontSize: 11, fontWeight: 700, borderRadius: 4,
        border: isPlaying ? "1px solid var(--signal-amber)" : "1px solid var(--signal-cyan)",
        background: isPlaying ? "var(--signal-amber-dim)" : "var(--signal-cyan-dim)",
        color: isPlaying ? "var(--signal-amber)" : "var(--signal-cyan)",
        cursor: disabled ? "default" : "pointer",
        letterSpacing: "0.06em",
        transition: "background 0.25s, border-color 0.25s, color 0.25s",
        opacity: disabled ? 0.5 : 1,
      }}
    >
      {isPlaying ? (
        <svg width={10} height={12} viewBox="0 0 10 12" fill="currentColor">
          <rect x="0" y="0" width="3.5" height="12" rx="1" />
          <rect x="6.5" y="0" width="3.5" height="12" rx="1" />
        </svg>
      ) : (
        <svg width={10} height={12} viewBox="0 0 10 12" fill="currentColor">
          <polygon points="0,0 10,6 0,12" />
        </svg>
      )}
      {isPlaying ? "PAUSE" : "PLAY"}
    </button>
  );
}

function LiveToggle({ liveMode, onToggle, backendConnected }) {
  const color = liveMode
    ? backendConnected ? "var(--signal-green)" : "var(--signal-amber)"
    : "var(--text-tertiary)";
  const label = liveMode
    ? backendConnected ? "LIVE ●" : "LIVE…"
    : "LIVE";
  return (
    <button
      onClick={onToggle}
      title={liveMode ? "Disconnect from backend (switch to demo mode)" : "Connect to Python backend (real ML models)"}
      style={{
        display: "flex", alignItems: "center", gap: 6,
        padding: "5px 12px", fontSize: 10.5, fontWeight: 700, borderRadius: 4,
        border: `1px solid ${liveMode ? color : "var(--line-strong)"}`,
        background: liveMode ? "rgba(61,220,151,0.08)" : "transparent",
        color,
        cursor: "pointer",
        letterSpacing: "0.1em",
        fontFamily: "var(--font-mono)",
        transition: "all 0.25s",
      }}
    >
      {liveMode && (
        <span style={{
          width: 6, height: 6, borderRadius: "50%",
          background: backendConnected ? "var(--signal-green)" : "var(--signal-amber)",
          animation: backendConnected ? "blink 1.5s ease-in-out infinite" : "none",
          flexShrink: 0,
        }} />
      )}
      {label}
    </button>
  );
}

export default function ControlPanel({
  scenario, onScenarioChange,
  isPlaying, onTogglePlay,
  speed, onSpeedChange,
  onReset, loading,
  liveMode, onLiveModeToggle, backendConnected,
  injectionActive, onInjectAttack,
}) {
  const [injectTarget, setInjectTarget] = useState("dos");
  return (
    <div
      style={{
        display: "flex", alignItems: "center", gap: 10,
        padding: "6px 16px",
        background: "var(--bg-panel)",
        borderBottom: "1px solid var(--line)",
        flexShrink: 0,
        flexWrap: "nowrap",
        minWidth: 0,
      }}
    >
      <span style={{
        fontSize: 9, fontWeight: 700, color: "var(--text-tertiary)",
        textTransform: "uppercase", letterSpacing: "0.1em", flexShrink: 0,
      }}>
        Scenario
      </span>

      <div style={{ width: 1, height: 16, background: "var(--line-strong)", flexShrink: 0 }} />

      {/* Scenario pills */}
      <div style={{ display: "flex", gap: 6 }}>
        {Object.entries(SCENARIOS).map(([key, s]) => (
          <ScenarioPill
            key={key}
            scenarioKey={key}
            label={s.label}
            selected={scenario === key}
            onClick={() => onScenarioChange(key)}
            disabled={loading}
          />
        ))}
      </div>

      <div style={{ width: 1, height: 16, background: "var(--line-strong)", flexShrink: 0 }} />

      {/* Inject Attack section */}
      <span style={{
        fontSize: 9, fontWeight: 700, color: "var(--text-tertiary)",
        textTransform: "uppercase", letterSpacing: "0.1em", flexShrink: 0,
      }}>
        Inject
      </span>

      <div style={{ display: "flex", gap: 4, flexShrink: 0 }}>
        {["dos", "fuzzy", "spoof"].map((key) => {
          const acc = SCENARIO_ACCENT[key];
          const label = key === "dos" ? "DoS" : key.charAt(0).toUpperCase() + key.slice(1);
          return (
            <button
              key={key}
              onClick={() => setInjectTarget(key)}
              disabled={loading}
              style={{
                padding: "2px 8px", fontSize: 10, fontWeight: 600, borderRadius: 20,
                border: `1px solid ${injectTarget === key ? acc.color : "var(--line-strong)"}`,
                background: injectTarget === key ? acc.dim : "transparent",
                color: injectTarget === key ? acc.color : "var(--text-tertiary)",
                cursor: loading ? "default" : "pointer",
                opacity: loading ? 0.5 : 1,
                transition: "all 0.15s",
              }}
            >
              {label}
            </button>
          );
        })}
      </div>

      <button
        onClick={() => onInjectAttack(injectTarget)}
        disabled={loading}
        style={{
          display: "flex", alignItems: "center", gap: 5,
          padding: "4px 12px", fontSize: 10.5, fontWeight: 700, borderRadius: 4,
          border: `1px solid ${injectionActive ? "var(--signal-red)" : "var(--signal-cyan)"}`,
          background: injectionActive ? "var(--signal-red-dim)" : "var(--signal-cyan-dim)",
          color: injectionActive ? "var(--signal-red)" : "var(--signal-cyan)",
          cursor: loading ? "default" : "pointer",
          opacity: loading ? 0.5 : 1,
          letterSpacing: "0.08em",
          transition: "all 0.2s",
          flexShrink: 0,
        }}
      >
        {injectionActive ? (
          <>
            <span style={{
              width: 6, height: 6, borderRadius: "50%",
              background: "var(--signal-red)",
              animation: "blink 1s ease-in-out infinite",
              flexShrink: 0,
            }} />
            INJECTING
          </>
        ) : (
          <>
            <svg width={7} height={9} viewBox="0 0 7 9" fill="currentColor" style={{ flexShrink: 0 }}>
              <polygon points="0,0 7,4.5 0,9" />
            </svg>
            INJECT
          </>
        )}
      </button>

      <div style={{ flex: 1 }} />

      {/* Speed slider */}
      <div style={{ display: "flex", alignItems: "center", gap: 6, flexShrink: 0 }}>
        <span style={{ fontSize: 9, color: "var(--text-tertiary)", letterSpacing: "0.06em", textTransform: "uppercase" }}>
          Speed
        </span>
        <input
          type="range" min="1" max="50" value={speed}
          onChange={(e) => onSpeedChange(Number(e.target.value))}
          style={{ width: 70, accentColor: "var(--signal-cyan)" }}
        />
        <span className="mono" style={{ fontSize: 10, color: "var(--signal-cyan)", minWidth: 22 }}>
          {speed}x
        </span>
      </div>

      <div style={{ width: 1, height: 16, background: "var(--line-strong)", flexShrink: 0 }} />

      {/* Live mode toggle */}
      <LiveToggle liveMode={liveMode} onToggle={onLiveModeToggle} backendConnected={backendConnected} />

      {/* Reset */}
      <button
        onClick={onReset}
        style={{
          padding: "4px 11px", fontSize: 10.5, fontWeight: 600, borderRadius: 4,
          border: "1px solid var(--line-strong)", background: "transparent",
          color: "var(--text-tertiary)", cursor: "pointer", letterSpacing: "0.04em",
          transition: "border-color 0.2s, color 0.2s",
        }}
        onMouseEnter={(e) => { e.target.style.borderColor = "var(--text-secondary)"; e.target.style.color = "var(--text-secondary)"; }}
        onMouseLeave={(e) => { e.target.style.borderColor = "var(--line-strong)"; e.target.style.color = "var(--text-tertiary)"; }}
      >
        Reset
      </button>

      {/* Play/Pause */}
      <PlayButton isPlaying={isPlaying} onClick={onTogglePlay} disabled={loading} />
    </div>
  );
}
