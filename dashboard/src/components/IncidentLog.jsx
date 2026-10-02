function formatScore(mlScores) {
  const entries = Object.entries(mlScores || {});
  if (!entries.length) return null;
  const [name, value] = entries[0];
  return `${name.toUpperCase()} p=${value.probability.toFixed(4)} / th=${value.threshold.toFixed(4)}`;
}

export default function IncidentLog({ incidents }) {
  return (
    <div data-testid="incident-log" style={{ background: "var(--bg-panel)", border: "1px solid var(--line)", borderRadius: "var(--radius)", overflow: "hidden", display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--line)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
          Hybrid-v4 evidence log
        </span>
        <span className="mono" data-testid="incident-count" style={{ fontSize: 11, color: "var(--text-tertiary)" }}>
          {incidents.length} total
        </span>
      </div>
      <div style={{ flex: 1, overflowY: "auto" }}>
        {incidents.length === 0 && (
          <div data-testid="no-incidents" style={{ padding: 20, color: "var(--text-tertiary)", fontSize: 12, textAlign: "center" }}>
            No incidents — bus is clean
          </div>
        )}
        {[...incidents].reverse().map((inc) => {
          const scoreText = formatScore(inc.mlScores);
          return (
            <div key={inc.id} data-testid="incident-row" style={{ padding: "12px 14px", borderBottom: "1px solid var(--line)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: "var(--signal-red)" }}>{inc.attackType}</span>
                <span className="mono" style={{ fontSize: 10, color: "var(--text-tertiary)" }}>t={Number(inc.windowStart).toFixed(2)}s</span>
              </div>
              <div className="mono" style={{ fontSize: 11, color: "var(--text-primary)", marginBottom: 4 }}>
                CAN 0x{inc.canId} · {inc.actionTaken}
              </div>
              <div className="mono" style={{ fontSize: 10, color: "var(--signal-cyan)", marginBottom: 5 }}>
                {(inc.reasonCodes || []).join(" + ")}
              </div>
              {scoreText && (
                <div className="mono" style={{ fontSize: 9.5, color: "var(--signal-amber)", marginBottom: 6 }}>{scoreText}</div>
              )}
              <ul style={{ margin: 0, paddingLeft: 16, fontSize: 10.5, color: "var(--text-tertiary)" }}>
                {(inc.reasons || []).map((reason, i) => <li key={i} style={{ marginBottom: 2 }}>{reason}</li>)}
              </ul>
              <div style={{ marginTop: 7, display: "flex", gap: 6, alignItems: "center" }}>
                <div style={{ flex: 1, height: 3, background: "var(--bg-inset)", borderRadius: 2, overflow: "hidden" }}>
                  <div style={{ width: `${Math.min(100, Number(inc.confidence || 0) * 100)}%`, height: "100%", background: Number(inc.confidence) > 0.8 ? "var(--signal-red)" : "var(--signal-amber)" }} />
                </div>
                <span className="mono" style={{ fontSize: 9.5, color: "var(--text-tertiary)" }}>
                  {(Number(inc.confidence || 0) * 100).toFixed(1)}%
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
