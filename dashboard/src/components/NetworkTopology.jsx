import { useEffect, useRef } from "react";
import * as d3 from "d3";
import { getEcuName } from "../data/loadCanData";
import CanTrafficOverlay from "./CanTrafficOverlay";

const STATUS_COLOR = {
  normal:    "var(--signal-cyan)",
  suspicious:"var(--signal-amber)",
  collateral:"var(--signal-amber)",
  isolated:  "var(--signal-red)",
};

const ECU_ORDER = ["0316", "018F", "0260", "02A0", "0329", "0153", "043F", "05A0", "0220", "04B1"];

const W = 640, H = 500, CX = W / 2, CY = H / 2, RADIUS = 185;

const NODE_POS = Object.fromEntries(
  ECU_ORDER.map((id, i) => {
    const angle = (i / ECU_ORDER.length) * 2 * Math.PI - Math.PI / 2;
    return [id, { x: CX + RADIUS * Math.cos(angle), y: CY + RADIUS * Math.sin(angle) }];
  })
);

export default function NetworkTopology({ networkState, recentAttackerIds, scenario = "normal", isPlaying = false }) {
  const svgRef = useRef(null);

  useEffect(() => {
    const svg = d3.select(svgRef.current);
    svg.attr("viewBox", `0 0 ${W} ${H}`);

    const nodes = ECU_ORDER.map((id) => ({
      id,
      x: NODE_POS[id].x,
      y: NODE_POS[id].y,
      status: networkState[id] || "normal",
    }));
    const gw = { x: CX, y: CY };

    // ── Defs (once) ──────────────────────────────────────────────────────────
    if (svg.select("defs").empty()) {
      const defs = svg.append("defs");
      const gwGrad = defs.append("radialGradient").attr("id", "gw-glow-grad")
        .attr("cx", "50%").attr("cy", "50%").attr("r", "50%");
      gwGrad.append("stop").attr("offset", "0%").attr("stop-color", "#4fd1e8").attr("stop-opacity", 0.18);
      gwGrad.append("stop").attr("offset", "100%").attr("stop-color", "#4fd1e8").attr("stop-opacity", 0);
    }

    let root = svg.select("g.topo");
    if (root.empty()) root = svg.append("g").attr("class", "topo");

    // ── Spoke lines ──────────────────────────────────────────────────────────
    const spokes = root.selectAll("line.spoke").data(nodes, (d) => d.id);
    const enteredSpokes = spokes.enter()
      .append("line").attr("class", "spoke")
      .attr("x1", (d) => d.x).attr("y1", (d) => d.y)
      .attr("x2", gw.x).attr("y2", gw.y);

    spokes.merge(enteredSpokes)
      .attr("stroke", (d) => STATUS_COLOR[d.status] || "var(--signal-cyan)")
      .attr("stroke-width", (d) => d.status === "normal" ? 1 : 1.5)
      .attr("opacity", (d) => {
        if (d.status === "isolated")  return 0.2;
        if (d.status === "suspicious" || d.status === "collateral") return 0.8;
        return 0.4;
      })
      .style("stroke-dasharray", (d) => d.status === "isolated" ? "4,8" : "3,11")
      .style("animation", (d) => {
        if (d.status === "isolated") return "none";
        const dur = (d.status === "suspicious" || d.status === "collateral") ? "0.32s" : "1s";
        return `flow-forward ${dur} linear infinite`;
      });

    // ── Gateway node ─────────────────────────────────────────────────────────
    let gwG = root.select("g.gw-node");
    if (gwG.empty()) {
      gwG = root.append("g").attr("class", "gw-node");
      gwG.append("circle")
        .attr("cx", gw.x).attr("cy", gw.y).attr("r", 58)
        .attr("fill", "url(#gw-glow-grad)").attr("stroke", "none");
      gwG.append("circle")
        .attr("cx", gw.x).attr("cy", gw.y).attr("r", 33)
        .attr("fill", "var(--bg-panel-raised)")
        .attr("stroke", "var(--signal-cyan)").attr("stroke-width", 1.5);
      gwG.append("circle")
        .attr("class", "gw-ring")
        .attr("cx", gw.x).attr("cy", gw.y).attr("r", 23)
        .attr("fill", "none")
        .attr("stroke", "var(--signal-cyan)").attr("stroke-width", 1)
        .attr("stroke-dasharray", "6,5").attr("opacity", 0.45)
        .style("animation", "spin-cw 8s linear infinite");
      gwG.append("text")
        .attr("x", gw.x).attr("y", gw.y - 5)
        .attr("text-anchor", "middle")
        .attr("font-family", "var(--font-mono)").attr("font-size", "9px").attr("font-weight", "700")
        .attr("fill", "var(--signal-cyan)").attr("letter-spacing", "0.08em")
        .text("GATEWAY");
      gwG.append("text")
        .attr("x", gw.x).attr("y", gw.y + 8)
        .attr("text-anchor", "middle")
        .attr("font-family", "var(--font-mono)").attr("font-size", "8px")
        .attr("fill", "var(--text-tertiary)").text("IDS");
    }

    // ── ECU nodes ─────────────────────────────────────────────────────────────
    const nodeGs = root.selectAll("g.ecu-node").data(nodes, (d) => d.id);

    const entered = nodeGs.enter()
      .append("g").attr("class", "ecu-node")
      .attr("transform", (d) => `translate(${d.x},${d.y})`);

    entered.append("circle").attr("class", "ecu-ring").attr("r", 31).attr("fill", "none").attr("stroke-width", 1);
    entered.append("circle").attr("class", "ecu-body").attr("r", 24).attr("stroke-width", 1.5);
    entered.append("text").attr("class", "ecu-id")
      .attr("y", -3).attr("text-anchor", "middle")
      .attr("font-family", "var(--font-mono)").attr("font-size", "10px").attr("font-weight", "700")
      .text((d) => `0x${d.id}`);
    entered.append("text").attr("class", "ecu-sys")
      .attr("y", 10).attr("text-anchor", "middle")
      .attr("font-family", "var(--font-mono)").attr("font-size", "8.5px")
      .attr("fill", "var(--text-secondary)")
      .text((d) => getEcuName(d.id).split(" ")[0]);
    entered.append("text").attr("class", "ecu-label")
      .attr("y", 46).attr("text-anchor", "middle")
      .attr("font-family", "var(--font-display)").attr("font-size", "11px")
      .attr("fill", "var(--text-primary)")
      .text((d) => getEcuName(d.id));

    const merged = entered.merge(nodeGs);

    merged.select("circle.ecu-body")
      .attr("fill", (d) => {
        if (d.status === "normal") return "var(--bg-panel-raised)";
        if (d.status === "isolated") return "var(--signal-red-dim)";
        return "var(--signal-amber-dim)"; // suspicious + collateral
      })
      .attr("stroke", (d) => STATUS_COLOR[d.status] || "var(--signal-cyan)")
      .style("filter", (d) => {
        if (d.status === "isolated")   return "drop-shadow(0 0 7px rgba(255,77,94,0.7))";
        if (d.status === "collateral") return "drop-shadow(0 0 6px rgba(255,178,56,0.5))";
        if (d.status === "suspicious") return "drop-shadow(0 0 6px rgba(255,178,56,0.6))";
        return "drop-shadow(0 0 3px rgba(79,209,232,0.3))";
      });

    merged.select("circle.ecu-ring")
      .attr("stroke", (d) => STATUS_COLOR[d.status] || "var(--signal-cyan)")
      .attr("opacity", (d) => d.status === "normal" ? 0.18 : 0.65)
      .attr("stroke-dasharray", (d) => d.status === "isolated" ? "3,5" : "none")
      .attr("class", (d) => {
        const anim = (d.status === "suspicious" || d.status === "collateral") ? " ecu-ring-anim" : "";
        return `ecu-ring${anim}`;
      });

    merged.select("text.ecu-id").attr("fill", (d) => STATUS_COLOR[d.status] || "var(--signal-cyan)");

    // ── Per-node badges: × for isolated, SOURCE/PROTECTED text labels ─────────
    merged.each(function (d) {
      const g = d3.select(this);

      // × mark for isolated nodes
      if (d.status === "isolated") {
        if (g.select("text.ecu-x").empty()) {
          g.append("text").attr("class", "ecu-x")
            .attr("y", 9).attr("text-anchor", "middle")
            .attr("font-size", "24px").attr("font-weight", "900")
            .attr("fill", "var(--signal-red)").attr("opacity", 0.45)
            .text("×");
        }
      } else {
        g.select("text.ecu-x").remove();
      }

      // Status badge below node label:
      //   isolated  → "SOURCE"    (red)  — this ID is the confirmed attacker
      //   collateral → "PROTECTED" (amber) — attribution gate shielded this ECU
      g.select("text.ecu-badge").remove();
      if (d.status === "isolated") {
        g.append("text").attr("class", "ecu-badge")
          .attr("y", 56).attr("text-anchor", "middle")
          .attr("font-family", "var(--font-mono)").attr("font-size", "10px")
          .attr("font-weight", "800").attr("fill", "var(--signal-red)")
          .attr("letter-spacing", "0.14em")
          .text("SOURCE");
      } else if (d.status === "collateral") {
        g.append("text").attr("class", "ecu-badge")
          .attr("y", 56).attr("text-anchor", "middle")
          .attr("font-family", "var(--font-mono)").attr("font-size", "9px")
          .attr("font-weight", "800").attr("fill", "var(--signal-amber)")
          .attr("letter-spacing", "0.1em")
          .text("PROTECTED");
      }
    });

  }, [networkState, recentAttackerIds]);

  return (
    <div style={{
      position: "relative",
      width: "min(100%, 680px)",
      margin: "0 auto",
    }}>
      <svg ref={svgRef} style={{ width: "100%", height: "auto", display: "block" }} />

      <CanTrafficOverlay
        width={W}
        height={H}
        cx={CX}
        cy={CY}
        ecuIds={ECU_ORDER}
        positions={NODE_POS}
        networkState={networkState}
        scenario={scenario}
        isPlaying={isPlaying}
      />

      {/* React-controlled overlay: shockwave rings on newly-isolated attacker nodes */}
      <svg
        viewBox={`0 0 ${W} ${H}`}
        style={{ position: "absolute", top: 0, left: 0, width: "100%", height: "100%", pointerEvents: "none" }}
      >
        {[...recentAttackerIds].map((id) => {
          const pos = NODE_POS[id];
          if (!pos) return null;
          return (
            <circle
              key={id}
              cx={pos.x}
              cy={pos.y}
              r={28}
              fill="none"
              stroke="var(--signal-red)"
              strokeWidth={2}
              style={{ animation: "shockwave-ring 0.95s ease-out forwards" }}
            />
          );
        })}
      </svg>

      <style>{`
        @keyframes shockwave-ring {
          0%   { r: 28px; opacity: 0.9; stroke-width: 2.5px; }
          100% { r: 100px; opacity: 0;  stroke-width: 0.3px; }
        }
        @keyframes ring-pulse {
          0%, 100% { opacity: 0.25; transform: scale(1); }
          50%       { opacity: 0.8;  transform: scale(1.1); }
        }
        .ecu-ring-anim {
          transform-box: fill-box;
          transform-origin: center;
          animation: ring-pulse 1.3s ease-in-out infinite;
        }
        .gw-ring {
          transform-box: fill-box;
          transform-origin: center;
        }
      `}</style>
    </div>
  );
}
