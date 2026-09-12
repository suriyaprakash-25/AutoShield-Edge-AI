import { useState, useEffect } from "react";

const SCENARIO_LABELS = {
  normal: "Normal traffic",
  dos:    "DoS attack",
  fuzzy:  "Fuzzy attack",
  spoof:  "Spoofing attack",
};

const THREAT = {
  secure:   { label: "SECURE",   color: "var(--signal-green)", bg: "var(--signal-green-dim)" },
  warning:  { label: "WARNING",  color: "var(--signal-amber)", bg: "var(--signal-amber-dim)" },
  critical: { label: "CRITICAL", color: "var(--signal-red)",   bg: "var(--signal-red-dim)"  },
};

// Training provenance constants — real numbers from validated Python pipeline.
// 19.6M = HCRL dataset Hyundai Sonata frame count; Recall verified across
// DoS/Fuzzy/Spoof in full_re_test_attributed.py.
const TRAINING_FRAMES = "19.6M";
const TRAINING_VEHICLE = "Hyundai Sonata";
const RECALL_PCT = "100%";

// ─── Live clock ───────────────────────────────────────────────────────────────
function Clock() {
  const [t, setT] = useState(() => new Date().toTimeString().slice(0, 8));
  useEffect(() => {
    const id = setInterval(() => setT(new Date().toTimeString().slice(0, 8)), 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <div style={{ textAlign: "right" }}>
      <div style={{ fontSize: 9, color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
        local time
      </div>
      <div className="mono" style={{ fontSize: 13, fontWeight: 600, color: "var(--text-secondary)", letterSpacing: "0.05em" }}>
        {t}
      </div>
    </div>
  );
}

// ─── Mini sparkline: message volume per window ────────────────────────────────
function Sparkline({ data }) {
  const W = 110, H = 28;
  if (!data || data.length < 2) return <div style={{ width: W, height: H }} />;
  const max = Math.max(...data, 1);
  const isSpike = max > 300;
  const color = isSpike ? "var(--signal-red)" : "var(--signal-cyan)";
  const pts = data
    .map((v, i) => `${(i / (data.length - 1)) * W},${H - (v / max) * H * 0.88}`)
    .join(" ");
  const fill = `0,${H} ${pts} ${W},${H}`;
  return (
    <svg width={W} height={H} style={{ display: "block", overflow: "visible" }}>
      <polyline points={fill}  fill={color} fillOpacity={0.07} stroke="none" />
      <polyline points={pts}   fill="none"  stroke={color}    strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

// ─── Shield SVG icon ─────────────────────────────────────────────────────────
function ShieldIcon({ isPlaying, threat }) {
  const stroke = threat ? "var(--signal-red)" : isPlaying ? "var(--signal-cyan)" : "var(--line-strong)";
  const fill   = threat ? "var(--signal-red-dim)" : isPlaying ? "var(--signal-cyan-dim)" : "var(--bg-panel-raised)";
  return (
    <div style={{ position: "relative", width: 34, height: 34, flexShrink: 0 }}>
      <svg width={34} height={34} viewBox="0 0 34 34" fill="none">
        <path
          d="M17 3 L30 8.5 L30 18 C30 25 23.5 30 17 32 C10.5 30 4 25 4 18 L4 8.5 Z"
          fill={fill}
          stroke={stroke}
          strokeWidth={1.5}
          style={{ transition: "fill 0.4s, stroke 0.4s" }}
        />
        <path
          d="M11.5 17 L15 20.5 L22.5 13"
          stroke={stroke}
          strokeWidth={2}
          strokeLinecap="round"
          strokeLinejoin="round"
          style={{ transition: "stroke 0.4s" }}
        />
      </svg>
      {isPlaying && (
        <div
          style={{
            position: "absolute",
            inset: 0,
            borderRadius: "50%",
            border: `1px solid ${stroke}`,
            animation: "shield-ping 2.5s ease-out infinite",
            pointerEvents: "none",
          }}
        />
      )}
    </div>
  );
}

// ─── Metric tile ─────────────────────────────────────────────────────────────
function Metric({ label, value, accent, mono }) {
  return (
    <div style={{ textAlign: "right" }}>
      <div style={{ fontSize: 9, color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.08em" }}>{label}</div>
      <div className={mono ? "mono" : ""} style={{ fontSize: 12, fontWeight: 600, color: accent || "var(--text-primary)", marginTop: 1 }}>
        {value}
      </div>
    </div>
  );
}

// ─── StatusBar ────────────────────────────────────────────────────────────────
export default function StatusBar({ scenario, isPlaying, frameIdx, totalFrames, latencyMs, msgHistory, alertEvent, liveMode, backendConnected }) {
  const underAttack = Boolean(alertEvent);
  const cfg = underAttack ? THREAT.critical
    : isPlaying && scenario !== "normal" ? THREAT.warning
    : THREAT.secure;

  return (
    <div style={{ flexShrink: 0 }}>
      {/* ── Main status bar row ────────────────────────────────────────────── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          height: 46,
          padding: "0 16px",
          background: underAttack ? "rgba(46, 16, 24, 0.95)" : "var(--bg-panel)",
          borderBottom: `1px solid ${underAttack ? "var(--signal-red)" : "var(--line)"}`,
          gap: 0,
          transition: "background 0.35s, border-color 0.35s",
        }}
      >
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          <ShieldIcon isPlaying={isPlaying} threat={underAttack} />
          <div>
            <div style={{ fontWeight: 700, fontSize: 12, letterSpacing: "0.03em", lineHeight: 1.2 }}>AutoShield Edge AI</div>
            <div style={{ fontSize: 9, color: "var(--text-tertiary)", letterSpacing: "0.02em" }}>in-vehicle network monitor</div>
          </div>
        </div>

        <div style={{ width: 1, height: 24, background: underAttack ? "rgba(255,77,94,0.3)" : "var(--line)", margin: "0 14px", transition: "background 0.35s" }} />

        {/* Threat level badge — centred */}
        <div style={{ flex: 1, display: "flex", justifyContent: "center" }}>
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 10,
              padding: "5px 18px",
              borderRadius: 4,
              background: cfg.bg,
              border: `1px solid ${cfg.color}`,
              animation: underAttack ? "critical-pulse 1.6s ease-in-out infinite" : "none",
              transition: "background 0.4s, border-color 0.4s",
            }}
          >
            <div
              style={{
                width: 7, height: 7, borderRadius: "50%",
                background: cfg.color,
                animation: isPlaying ? "blink 1.2s ease-in-out infinite" : "none",
              }}
            />
            <span className="mono" style={{ fontSize: underAttack ? 15 : 13, fontWeight: 800, color: cfg.color, letterSpacing: "0.14em", transition: "font-size 0.3s" }}>
              {cfg.label}
            </span>
            {(underAttack || (isPlaying && scenario !== "normal")) && (
              <>
                <span style={{ color: cfg.color, opacity: 0.35, fontSize: 14 }}>|</span>
                <span style={{ fontSize: 11, fontWeight: 600, color: cfg.color, opacity: 0.85 }}>
                  {SCENARIO_LABELS[scenario]}
                </span>
              </>
            )}
          </div>
        </div>

        <div style={{ width: 1, height: 24, background: underAttack ? "rgba(255,77,94,0.3)" : "var(--line)", margin: "0 14px", transition: "background 0.35s" }} />

        {/* Right: sparkline + metrics + clock */}
        <div style={{ display: "flex", alignItems: "center", gap: 14, flexShrink: 0 }}>
          <div>
            <div style={{ fontSize: 8.5, color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 2 }}>
              msg / window
            </div>
            <Sparkline data={msgHistory} />
          </div>
          <Metric label="frame" value={`${frameIdx.toLocaleString()} / ${totalFrames.toLocaleString()}`} mono />
          <Metric label="inference" value={`${latencyMs.toFixed(1)} ms`} mono accent="var(--signal-cyan)" />
          {liveMode && (
            <div
              style={{
                padding: "3px 9px",
                borderRadius: 3,
                border: `1px solid ${backendConnected ? "var(--signal-green)" : "var(--signal-amber)"}`,
                background: backendConnected ? "rgba(61,220,151,0.08)" : "rgba(255,178,56,0.08)",
                fontSize: 9.5,
                fontWeight: 700,
                color: backendConnected ? "var(--signal-green)" : "var(--signal-amber)",
                fontFamily: "var(--font-mono)",
                letterSpacing: "0.1em",
                flexShrink: 0,
              }}
            >
              {backendConnected ? "● LIVE MODEL" : "○ CONNECTING"}
            </div>
          )}
          <Clock />
        </div>
      </div>

      {/* ── Credibility strip ─────────────────────────────────────────────────
          Always-visible single line showing training provenance and live
          inference latency. Numbers must be real: frames count from HCRL
          dataset, recall from full_re_test_attributed.py, latency live-measured. */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 0,
          padding: "2px 16px",
          background: "var(--bg-inset)",
          borderBottom: "1px solid var(--line)",
          fontFamily: "var(--font-mono)",
          fontSize: 9,
          letterSpacing: "0.03em",
          overflow: "hidden",
          whiteSpace: "nowrap",
        }}
      >
        <span style={{ color: "var(--text-tertiary)" }}>
          Trained on {TRAINING_FRAMES} real {TRAINING_VEHICLE} CAN frames
        </span>
        <span style={{ color: "var(--line-strong)", margin: "0 8px" }}>·</span>
        <span style={{ color: "var(--signal-green)", fontWeight: 600 }}>
          Recall {RECALL_PCT}
        </span>
        <span style={{ color: "var(--line-strong)", margin: "0 8px" }}>·</span>
        <span style={{ color: "var(--signal-cyan)" }}>
          Inference {latencyMs.toFixed(1)} ms
        </span>
        <span style={{ color: "var(--line-strong)", margin: "0 8px" }}>·</span>
        <span style={{ color: "var(--text-tertiary)" }}>
          IsolationForest · attribution gate · entropy-drift suppression
        </span>
      </div>
    </div>
  );
}
