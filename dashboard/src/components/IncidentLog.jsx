// ─── Confidence arc gauge ─────────────────────────────────────────────────────
function ConfidenceArc({ confidence }) {
  const r = 18;
  const len = Math.PI * r; // half-circle circumference
  const filled = len * Math.min(confidence, 1);
  const color = confidence > 0.8 ? "var(--signal-red)" : confidence > 0.5 ? "var(--signal-amber)" : "var(--signal-cyan)";
  return (
    <svg width={44} height={24} viewBox="0 0 44 24" style={{ overflow: "visible" }}>
      <path d="M 4 22 A 18 18 0 0 1 40 22" fill="none" stroke="var(--bg-inset)" strokeWidth={4} strokeLinecap="round" />
      <path
        d="M 4 22 A 18 18 0 0 1 40 22"
        fill="none"
        stroke={color}
        strokeWidth={4}
        strokeDasharray={`${filled.toFixed(1)} ${len.toFixed(1)}`}
        strokeLinecap="round"
      />
      <text x="22" y="20" textAnchor="middle" fontSize="8" fontFamily="var(--font-mono)" fill="var(--text-secondary)">
        {(confidence * 100).toFixed(0)}%
      </text>
    </svg>
  );
}

// ─── Attack type badge color ───────────────────────────────────────────────────
function attackColor(type) {
  if (!type) return "var(--signal-red)";
  const t = type.toLowerCase();
  if (t.includes("dos"))   return "var(--signal-red)";
  if (t.includes("fuzzy")) return "var(--signal-amber)";
  if (t.includes("spoof")) return "var(--signal-purple)";
  return "var(--signal-red)";
}

// ─── Single incident card ─────────────────────────────────────────────────────
function IncidentCard({ inc }) {
  const isFuzzy = typeof inc.canId === "string" && inc.canId.includes("distinct");
  const aColor   = attackColor(inc.attackType);
  const isIsolated = inc.actionTaken && inc.actionTaken.toLowerCase().includes("isol");

  return (
    <div
      style={{
        padding: "10px 14px",
        borderBottom: "1px solid var(--line)",
        animation: "slide-in-right 0.28s ease-out",
        borderLeft: `3px solid ${aColor}`,
      }}
    >
      {/* Header row */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 5 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 3 }}>
            <span style={{ fontSize: 13, fontWeight: 800, color: aColor }}>{inc.attackType}</span>
            {isIsolated && (
              <span
                style={{
                  fontSize: 10,
                  fontWeight: 800,
                  color: "var(--signal-red)",
                  padding: "2px 6px",
                  border: "1px solid var(--signal-red)",
                  background: "var(--signal-red-dim)",
                  borderRadius: 2,
                  fontFamily: "var(--font-mono)",
                  letterSpacing: "0.1em",
                  flexShrink: 0,
                }}
              >
                ISOLATED
              </span>
            )}
          </div>
          <div className="mono" style={{ fontSize: 10, color: "var(--text-primary)" }}>
            {isFuzzy ? inc.canId : `0x${inc.canId}`}
          </div>
        </div>
        <div style={{ textAlign: "right", flexShrink: 0, marginLeft: 8 }}>
          <div className="mono" style={{ fontSize: 9, color: "var(--text-tertiary)", marginBottom: 2 }}>
            t={inc.windowStart.toFixed(2)}s
          </div>
          <ConfidenceArc confidence={inc.confidence} />
        </div>
      </div>

      {/* Reasons */}
      {inc.reasons && inc.reasons.length > 0 && (
        <ul style={{ margin: "4px 0 0 0", padding: "0 0 0 12px", listStyle: "disc" }}>
          {inc.reasons.map((r, i) => (
            <li key={i} style={{ fontSize: 9.5, color: "var(--text-tertiary)", marginBottom: 1, lineHeight: 1.4 }}>
              {r}
            </li>
          ))}
        </ul>
      )}

      {/* Action taken */}
      <div style={{ marginTop: 4, fontSize: 9.5, color: "var(--text-secondary)", fontStyle: "italic" }}>
        {inc.actionTaken}
      </div>
    </div>
  );
}

// ─── Incident log panel ───────────────────────────────────────────────────────
export default function IncidentLog({ incidents }) {
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
      {/* Header */}
      <div
        style={{
          padding: "8px 14px",
          borderBottom: "1px solid var(--line)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexShrink: 0,
        }}
      >
        <span style={{ fontSize: 10, fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "0.1em" }}>
          Incident log
        </span>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {incidents.length > 0 && (
            <span
              style={{
                padding: "1px 8px",
                background: "var(--signal-red-dim)",
                border: "1px solid var(--signal-red)",
                borderRadius: 3,
                fontSize: 10,
                fontWeight: 700,
                color: "var(--signal-red)",
                fontFamily: "var(--font-mono)",
              }}
            >
              {incidents.length}
            </span>
          )}
          <span className="mono" style={{ fontSize: 10, color: "var(--text-tertiary)" }}>
            {incidents.length === 0 ? "clean" : "total"}
          </span>
        </div>
      </div>

      {/* Cards */}
      <div style={{ flex: 1, overflowY: "auto" }}>
        {incidents.length === 0 ? (
          <div style={{ padding: 24, color: "var(--text-tertiary)", fontSize: 12, textAlign: "center" }}>
            <div style={{ marginBottom: 6, fontSize: 22 }}>✓</div>
            No incidents — bus is clean
          </div>
        ) : (
          [...incidents].reverse().map((inc) => (
            <IncidentCard key={inc.id} inc={inc} />
          ))
        )}
      </div>
    </div>
  );
}
