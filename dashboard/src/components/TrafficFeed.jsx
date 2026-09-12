import { getEcuName } from "../data/loadCanData";

// ─── Byte cell colormap ────────────────────────────────────────────────────────
// Map a byte value 0-255 → a hue on a 3-stop gradient (dark→teal→amber→red)
function byteColor(val) {
  if (val === 0) return "#1a2230";
  if (val < 64)  return `hsl(${190 + val * 0.5}, 60%, ${22 + val * 0.08}%)`;
  if (val < 192) return `hsl(${190 - (val - 64) * 1.1}, 65%, 30%)`;
  return `hsl(${10 + (255 - val) * 0.4}, 75%, ${30 + (val - 192) * 0.12}%)`;
}

// ─── One hex byte cell ────────────────────────────────────────────────────────
function ByteCell({ hex }) {
  const val = parseInt(hex, 16);
  const bg  = byteColor(isNaN(val) ? 0 : val);
  return (
    <span
      className="mono"
      style={{
        display: "inline-block",
        width: 20,
        height: 16,
        lineHeight: "16px",
        textAlign: "center",
        fontSize: 9.5,
        borderRadius: 2,
        background: bg,
        color: val > 64 ? "#d0dce8" : "#4e6070",
        flexShrink: 0,
      }}
    >
      {hex}
    </span>
  );
}

// ─── Single row ───────────────────────────────────────────────────────────────
function TrafficRow({ f }) {
  const isAttack = f.flag === "T";
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "68px 54px auto 1fr",
        gap: 10,
        padding: "4px 14px",
        alignItems: "center",
        background: isAttack ? "rgba(255,77,94,0.07)" : "transparent",
        borderLeft: isAttack ? "2px solid var(--signal-red)" : "2px solid transparent",
        transition: "background 0.2s",
      }}
    >
      {/* Timestamp */}
      <span className="mono" style={{ fontSize: 10.5, color: "var(--text-tertiary)" }}>
        {f.timestamp.toFixed(3)}
      </span>

      {/* CAN ID */}
      <span
        className="mono"
        style={{
          fontSize: 11,
          fontWeight: 700,
          color: isAttack ? "var(--signal-red)" : "var(--signal-cyan)",
        }}
      >
        0x{f.canId}
      </span>

      {/* Byte cells */}
      <div style={{ display: "flex", gap: 2 }}>
        {f.dataBytes.map((b, i) => (
          <ByteCell key={i} hex={b} />
        ))}
      </div>

      {/* ECU name */}
      <span
        style={{
          fontSize: 9.5,
          color: isAttack ? "var(--signal-red)" : "var(--text-tertiary)",
          textAlign: "right",
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
          opacity: isAttack ? 1 : 0.75,
        }}
      >
        {getEcuName(f.canId)}
        {isAttack && (
          <span
            style={{
              marginLeft: 6,
              fontSize: 8.5,
              fontWeight: 700,
              padding: "1px 5px",
              border: "1px solid var(--signal-red)",
              borderRadius: 2,
              color: "var(--signal-red)",
              letterSpacing: "0.08em",
              fontFamily: "var(--font-mono)",
            }}
          >
            INJECTED
          </span>
        )}
      </span>
    </div>
  );
}

// ─── Header row ───────────────────────────────────────────────────────────────
function ColumnHeaders() {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "68px 54px auto 1fr",
        gap: 10,
        padding: "4px 14px",
        borderBottom: "1px solid var(--line)",
      }}
    >
      {["time (s)", "CAN ID", "payload bytes", "ECU"].map((h) => (
        <span key={h} style={{ fontSize: 9, color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
          {h}
        </span>
      ))}
    </div>
  );
}

// ─── Traffic feed panel ───────────────────────────────────────────────────────
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
      {/* Panel header */}
      <div
        style={{
          padding: "6px 12px",
          borderBottom: "1px solid var(--line)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexShrink: 0,
        }}
      >
        <span style={{ fontSize: 10, fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "0.1em" }}>
          Live CAN traffic
        </span>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: "#162830", display: "inline-block", border: "1px solid #1a2e38" }} />
            <span style={{ fontSize: 9, color: "var(--text-tertiary)" }}>0x00</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: "hsl(190,65%,30%)", display: "inline-block" }} />
            <span style={{ fontSize: 9, color: "var(--text-tertiary)" }}>mid</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: "hsl(10,75%,36%)", display: "inline-block" }} />
            <span style={{ fontSize: 9, color: "var(--text-tertiary)" }}>0xFF</span>
          </div>
        </div>
      </div>

      <ColumnHeaders />

      {/* Rows */}
      <div style={{ flex: 1, overflowY: "auto" }}>
        {frames.length === 0 ? (
          <div style={{ padding: 20, color: "var(--text-tertiary)", fontSize: 12, textAlign: "center" }}>
            No traffic yet — press play
          </div>
        ) : (
          frames.map((f, i) => <TrafficRow key={i} f={f} />)
        )}
      </div>
    </div>
  );
}
