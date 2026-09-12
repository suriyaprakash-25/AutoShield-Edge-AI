import { useState, useEffect, useRef, useCallback } from "react";
import { loadCanCsv, SCENARIOS } from "./data/loadCanData";
import { buildBaselineProfile, extractWindowFeatures } from "./lib/featureExtraction";
import { scoreWindow, classifyAttackType, computeBaselineStats } from "./lib/detector";
import { createResponseEngine } from "./lib/responseEngine";
import useBackend from "./hooks/useBackend";
import StatusBar from "./components/StatusBar";
import ControlPanel from "./components/ControlPanel";
import NetworkTopology from "./components/NetworkTopology";
import TrafficFeed from "./components/TrafficFeed";
import IncidentLog from "./components/IncidentLog";

const WINDOW_MS = 200;
const KNOWN_IDS = new Set(["0316", "018F", "0260", "02A0", "0329", "0153", "043F", "05A0", "0220", "04B1"]);

// ─── Alert banner (thin, auto-dismiss) ────────────────────────────────────────
function AlertBanner({ event }) {
  if (!event) return null;
  const isFuzzy = typeof event.canId === "string" && event.canId.includes("distinct");
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 14,
        padding: "6px 20px",
        background: "var(--signal-red-dim)",
        borderBottom: "1px solid var(--signal-red)",
        animation: "slide-in-top 0.2s ease-out",
        flexShrink: 0,
      }}
    >
      <span style={{ fontSize: 12, fontWeight: 800, color: "var(--signal-red)", letterSpacing: "0.12em", flexShrink: 0 }}>
        ⚠ THREAT DETECTED
      </span>
      <Sep />
      <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text-primary)", flexShrink: 0 }}>{event.attackType}</span>
      <Sep />
      <span className="mono" style={{ fontSize: 11, color: "var(--text-secondary)", flexShrink: 0 }}>
        {isFuzzy ? event.canId : `ECU 0x${event.canId}`}
      </span>
      <Sep />
      <span className="mono" style={{ fontSize: 11, color: "var(--signal-amber)", flexShrink: 0 }}>
        {(event.confidence * 100).toFixed(0)}% confidence
      </span>
      <div style={{ flex: 1 }} />
      <div
        style={{
          padding: "3px 12px",
          border: "1px solid var(--signal-red)",
          borderRadius: 3,
          fontSize: 10,
          fontWeight: 700,
          color: "var(--signal-red)",
          fontFamily: "var(--font-mono)",
          letterSpacing: "0.12em",
          flexShrink: 0,
        }}
      >
        ECU ISOLATED
      </div>
    </div>
  );
}

function Sep() {
  return <span style={{ color: "var(--line-strong)", fontSize: 18 }}>|</span>;
}

// ─── Explainability hero panel ─────────────────────────────────────────────────
// Shows the actual detector reason strings (from JS detector.js scoreWindow())
// when an attack is active. Not hardcoded — populated from score.reasons which
// mirror the Python detector.py explain() output format exactly.
function ExplainPanel({ event }) {
  if (!event || !event.reasons || event.reasons.length === 0) return null;
  const isFuzzy = typeof event.canId === "string" && event.canId.includes("distinct");
  const sourceLabel = isFuzzy ? event.canId : `0x${event.canId}`;
  const attackLabel = (event.attackType || "ANOMALY").toUpperCase();
  return (
    <div
      style={{
        padding: "7px 12px",
        background: "rgba(10,3,6,0.9)",
        border: "1px solid rgba(255,77,94,0.35)",
        borderRadius: "var(--radius)",
        flexShrink: 0,
        animation: "slide-in-right 0.22s ease-out",
      }}
    >
      <div style={{ marginBottom: 5, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span className="mono" style={{ fontSize: 9.5, fontWeight: 800, color: "var(--signal-red)", letterSpacing: "0.12em" }}>
          WHY FLAGGED
        </span>
        <span style={{ fontSize: 9, color: "var(--text-tertiary)", fontFamily: "var(--font-mono)" }}>|</span>
        <span className="mono" style={{ fontSize: 9.5, fontWeight: 700, color: "var(--text-primary)" }}>
          {attackLabel}
        </span>
        <span style={{ fontSize: 9, color: "var(--text-tertiary)", fontFamily: "var(--font-mono)" }}>|</span>
        <span className="mono" style={{ fontSize: 9.5, color: "var(--signal-amber)" }}>
          Source: {sourceLabel}
        </span>
      </div>
      {event.reasons.map((r, i) => (
        <div
          key={i}
          style={{
            display: "flex",
            alignItems: "flex-start",
            gap: 6,
            marginBottom: i < event.reasons.length - 1 ? 3 : 0,
          }}
        >
          <span style={{ color: "var(--signal-red)", fontSize: 9, flexShrink: 0, marginTop: 1 }}>▸</span>
          <span style={{ fontSize: 10, color: "var(--text-secondary)", lineHeight: 1.4 }}>{r}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Threat panel ─────────────────────────────────────────────────────────────
function ThreatPanel({ alertEvent, totalFramesBlocked, networkState, liveMode, modelType }) {
  const levels     = Object.values(networkState);
  const isolated   = levels.filter((s) => s === "isolated").length;
  const collateral = levels.filter((s) => s === "collateral").length;
  const suspicious = levels.filter((s) => s === "suspicious").length;
  const normal     = levels.filter((s) => s === "normal").length;

  const isAlert = alertEvent || isolated > 0;
  const label   = alertEvent ? "CRITICAL" : isolated > 0 ? "ALERT" : suspicious > 0 || collateral > 0 ? "WARNING" : "SECURE";
  const color   = alertEvent ? "var(--signal-red)"
    : isolated > 0 ? "var(--signal-red)"
    : suspicious > 0 || collateral > 0 ? "var(--signal-amber)"
    : "var(--signal-green)";

  return (
    <div
      style={{
        background: "var(--bg-panel)",
        borderRadius: "var(--radius)",
        padding: "14px 16px",
        marginBottom: 0,
        flexShrink: 0,
        border: isAlert ? "1px solid rgba(255,77,94,0.4)" : "1px solid var(--line)",
        animation: isAlert ? "critical-pulse 1.8s ease-in-out infinite" : "none",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 8 }}>
        <div>
          <div style={{ fontSize: 8.5, color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 3 }}>
            System threat level
          </div>
          <div
            className="mono"
            style={{ fontSize: 30, fontWeight: 800, color, letterSpacing: "0.06em", lineHeight: 1, transition: "color 0.4s" }}
          >
            {label}
          </div>
          {liveMode && modelType && (
            <div style={{ marginTop: 3, fontSize: 8.5, color: "var(--signal-purple)", fontFamily: "var(--font-mono)", letterSpacing: "0.06em" }}>
              {modelType}
            </div>
          )}
        </div>
        {/* Frames-blocked counter — ticks in real time from backend framesBlocked field */}
        <div style={{ textAlign: "right" }}>
          <div style={{ fontSize: 8.5, color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 3 }}>
            Frames blocked
          </div>
          <div
            className="mono"
            style={{
              fontSize: 46,
              fontWeight: 800,
              lineHeight: 1,
              color: totalFramesBlocked > 0 ? "var(--signal-red)" : "var(--text-tertiary)",
              transition: "color 0.3s",
              fontVariantNumeric: "tabular-nums",
            }}
          >
            {totalFramesBlocked > 9999
              ? `${(totalFramesBlocked / 1000).toFixed(1)}k`
              : String(totalFramesBlocked).padStart(2, "0")}
          </div>
        </div>
      </div>

      {/* ECU status pills — four states reflecting the attribution gate */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 5 }}>
        <Pill count={normal}     label="Normal"     color="var(--signal-cyan)"  />
        <Pill count={suspicious} label="Suspicious" color="var(--signal-amber)" />
        <Pill count={collateral} label="Protected"  color="var(--signal-amber)" dim />
        <Pill count={isolated}   label="Isolated"   color="var(--signal-red)"   />
      </div>
    </div>
  );
}

function Pill({ count, label, color, dim }) {
  const active = count > 0;
  return (
    <div
      style={{
        textAlign: "center", padding: "5px 3px",
        background: "var(--bg-inset)", borderRadius: 4,
        border: `1px solid ${active ? `${color}35` : "var(--line)"}`,
        transition: "border-color 0.3s",
        opacity: dim ? 0.85 : 1,
      }}
    >
      <div className="mono" style={{ fontSize: 15, fontWeight: 700, color: active ? color : "var(--text-tertiary)", lineHeight: 1 }}>
        {count}
      </div>
      <div style={{ fontSize: 8, color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.05em", marginTop: 2 }}>
        {label}
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [scenario, setScenario]     = useState("dos");
  const [loading, setLoading]       = useState(true);
  const [isPlaying, setIsPlaying]   = useState(false);
  const [speed, setSpeed]           = useState(10);
  const [liveMode, setLiveMode]     = useState(false);

  // Demo-mode (JS) assets
  const [baselineProfile, setBaselineProfile] = useState(null);
  const [baselineStats, setBaselineStats]     = useState(null);
  const [scenarioFrames, setScenarioFrames]   = useState({});

  // Shared display state
  const [visibleFrames, setVisibleFrames]         = useState([]);
  const [incidents, setIncidents]                 = useState([]);
  const [networkState, setNetworkState]           = useState({});
  const [recentAttackerIds, setRecentAttackerIds] = useState(new Set());
  const [latencyMs, setLatencyMs]                 = useState(0.8);
  const [alertEvent, setAlertEvent]               = useState(null);
  const [totalFramesBlocked, setTotalFramesBlocked] = useState(0);
  const [msgHistory, setMsgHistory]               = useState([]);
  const [backendError, setBackendError]           = useState(null);
  const [modeNotice, setModeNotice]               = useState(null);
  const [vignetteFlash, setVignetteFlash]         = useState(false);
  const [topoHeight, setTopoHeight]               = useState(510);

  const alertTimerRef    = useRef(null);
  const noticeTimerRef   = useRef(null);
  const prevAlertRef     = useRef(null);
  const topoHeightRef    = useRef(510);
  const engineRef        = useRef(null);
  const frameIdxRef      = useRef(0);
  const windowBufRef     = useRef([]);
  const lastWinRef       = useRef(null);
  const animRef          = useRef(null);
  // Per-ID normal msg_count_ratio — computed once from normal traffic features,
  // used to wire the attribution gate into createResponseEngine.
  const normalIdRatioRef    = useRef(null);
  const normalTsOffsetRef   = useRef(0);    // accumulated ts shift for looped normal traffic
  const attackInjectionRef  = useRef(null); // { frames, idx, tsOffset } | null — active injection
  const pendingInjectionRef = useRef(null); // { frames } | null — queued if scenario switch needed
  const [injectionActive, setInjectionActive] = useState(false);

  // ── Demo data loading ──────────────────────────────────────────────────────
  useEffect(() => {
    (async () => {
      setLoading(true);
      const normalFrames = await loadCanCsv(SCENARIOS.normal.file);
      const profile = buildBaselineProfile(normalFrames);
      const normalFeatures = extractWindowFeatures(normalFrames, WINDOW_MS, profile, KNOWN_IDS);
      const stats = computeBaselineStats(normalFeatures);

      // Compute per-ID mean msg_count_ratio from normal-traffic features.
      // This is the baseline each known ECU's share gets compared against in
      // the attribution gate: ratio > 3× this → attributed as flood source.
      const ratioSums = {}, ratioCounts = {};
      for (const row of normalFeatures) {
        ratioSums[row.canId]   = (ratioSums[row.canId]   || 0) + row.msgCountRatio;
        ratioCounts[row.canId] = (ratioCounts[row.canId] || 0) + 1;
      }
      normalIdRatioRef.current = Object.fromEntries(
        Object.keys(ratioSums).map((id) => [id, ratioSums[id] / ratioCounts[id]])
      );

      const loaded = { normal: normalFrames };
      for (const key of ["dos", "fuzzy", "spoof"]) {
        loaded[key] = await loadCanCsv(SCENARIOS[key].file);
      }
      setBaselineProfile(profile);
      setBaselineStats(stats);
      setScenarioFrames(loaded);
      setLoading(false);
    })();
  }, []);

  // ── Reset ──────────────────────────────────────────────────────────────────
  const resetSimulation = useCallback(() => {
    engineRef.current = createResponseEngine({ normalIdRatio: normalIdRatioRef.current });
    frameIdxRef.current = 0;
    windowBufRef.current = [];
    lastWinRef.current = null;
    normalTsOffsetRef.current = 0;
    attackInjectionRef.current = null;
    setInjectionActive(false);
    clearTimeout(alertTimerRef.current);
    setVisibleFrames([]);
    setIncidents([]);
    setNetworkState({});
    setRecentAttackerIds(new Set());
    setAlertEvent(null);
    setTotalFramesBlocked(0);
    setMsgHistory([]);
    setBackendError(null);
  }, []);

  useEffect(() => { resetSimulation(); }, [scenario, resetSimulation]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { if (!loading) resetSimulation(); }, [loading]);

  // Auto-dismiss alert banner after 5s of no new alerts
  useEffect(() => {
    if (!alertEvent) return;
    clearTimeout(alertTimerRef.current);
    alertTimerRef.current = setTimeout(() => setAlertEvent(null), 5000);
    return () => clearTimeout(alertTimerRef.current);
  }, [alertEvent]);

  // Full-viewport vignette flash on first attack detection each session
  useEffect(() => {
    if (alertEvent && !prevAlertRef.current) {
      setVignetteFlash(true);
      const t = setTimeout(() => setVignetteFlash(false), 850);
      return () => clearTimeout(t);
    }
    prevAlertRef.current = alertEvent;
  }, [alertEvent]);

  // ── Incident handlers ──────────────────────────────────────────────────────
  const handleIncident = useCallback((incident) => {
    setIncidents((prev) => [...prev, incident]);
    setAlertEvent(incident);
    if (typeof incident.canId === "string" && !incident.canId.includes("distinct")) {
      setRecentAttackerIds(new Set([incident.canId]));
      setTimeout(() => setRecentAttackerIds(new Set()), 900);
    }
  }, []);

  // For fuzzy-burst aggregation: the engine mutates activeFuzzyIncident in
  // place and returns it so we can replace the existing state entry by id,
  // triggering a re-render with the updated "N distinct IDs" count.
  const handleFuzzyUpdate = useCallback((incident) => {
    setIncidents((prev) => prev.map((inc) => inc.id === incident.id ? { ...incident } : inc));
  }, []);

  // ── Backend hook ──────────────────────────────────────────────────────────
  const backend = useBackend({
    onFrameBatch: useCallback((frames) => {
      frameIdxRef.current += frames.length;
      setVisibleFrames((prev) => [...prev, ...frames].slice(-60));
      setMsgHistory((prev) => [...prev.slice(-39), frames.length]);
    }, []),

    onWindowResult: useCallback(({ networkState: ns, incidents: incs, latencyMs: lms, framesBlocked: fb }) => {
      if (ns) setNetworkState(ns);
      if (lms) setLatencyMs(lms);
      if (fb > 0) setTotalFramesBlocked((prev) => prev + fb);
      for (const inc of incs || []) handleIncident(inc);
    }, [handleIncident]),

    onStatusChange: useCallback((state) => {
      if (state === "done") setIsPlaying(false);
    }, []),

    onError: useCallback((msg) => {
      setBackendError(msg);
      setLiveMode(false);
      setIsPlaying(false);
    }, []),
  });

  // ── Attack injection into live normal stream ───────────────────────────────
  // Only injects flag="T" frames — the looping normal stream already supplies
  // background ECU traffic, so injecting only the attack packets avoids
  // double-counting known ECUs' msg_count_ratio (which would confuse the
  // attribution gate).
  const handleInjectAttack = useCallback((attackScenario) => {
    if (loading) return;
    const allFrames = scenarioFrames[attackScenario];
    if (!allFrames?.length) return;
    const attackFrames = allFrames.filter((f) => f.flag === "T");
    if (!attackFrames.length) return;

    if (liveMode) {
      // Clicking Inject while connected to the backend drops back to JS demo mode
      // and queues the injection — same flow as a scenario change, but also
      // disconnects the WebSocket so the two pipelines don't fight each other.
      backend.disconnect();
      setLiveMode(false);
      resetSimulation();
      clearTimeout(noticeTimerRef.current);
      setModeNotice("Live disconnected — running injection in Demo mode");
      noticeTimerRef.current = setTimeout(() => setModeNotice(null), 3500);
      pendingInjectionRef.current = { frames: attackFrames };
      setScenario("normal");
      setIsPlaying(true);
      return;
    }

    if (scenario === "normal" && isPlaying) {
      // Already streaming normal traffic — inject immediately
      const normalFrames = scenarioFrames["normal"];
      const curIdx = Math.max(0, Math.min(frameIdxRef.current - 1, normalFrames.length - 1));
      const curTs = normalFrames[curIdx].timestamp + normalTsOffsetRef.current;
      attackInjectionRef.current = { frames: attackFrames, idx: 0, tsOffset: curTs - attackFrames[0].timestamp };
      setInjectionActive(true);
    } else {
      // Queue injection; the tick loop picks it up on its first run after the
      // scenario switches to "normal" — pendingInjectionRef is NOT cleared by
      // resetSimulation so it survives the scenario-change reset.
      pendingInjectionRef.current = { frames: attackFrames };
      if (scenario !== "normal") setScenario("normal");
      setIsPlaying(true);
    }
  }, [liveMode, loading, scenario, isPlaying, scenarioFrames, backend, resetSimulation]);

  // ── Demo (JS) play loop ────────────────────────────────────────────────────
  useEffect(() => {
    if (liveMode || !isPlaying || loading) return;
    const frames = scenarioFrames[scenario];
    if (!frames?.length) return;
    const isNormal = scenario === "normal";

    function tick() {
      // Activate any queued injection on the first tick after switching to normal
      if (isNormal && pendingInjectionRef.current) {
        const pending = pendingInjectionRef.current;
        pendingInjectionRef.current = null;
        const curTs = frames[0].timestamp + normalTsOffsetRef.current;
        attackInjectionRef.current = { frames: pending.frames, idx: 0, tsOffset: curTs - pending.frames[0].timestamp };
        setInjectionActive(true);
      }

      const startIdx = frameIdxRef.current;
      const endIdx   = Math.min(startIdx + speed, frames.length);

      // Build this tick's frame list.
      // Non-normal scenarios: use frames directly (no timestamp manipulation).
      // Normal scenario: apply looping timestamp offset, then time-range-merge
      // any active attack injection frames.
      const tickFrames = [];
      if (!isNormal) {
        for (let i = startIdx; i < endIdx; i++) tickFrames.push(frames[i]);
      } else {
        for (let i = startIdx; i < endIdx; i++) {
          const raw = frames[i];
          tickFrames.push(normalTsOffsetRef.current === 0 ? raw
            : { ...raw, timestamp: raw.timestamp + normalTsOffsetRef.current });
        }
        // Pull attack frames whose re-timestamped position falls in this tick's
        // time window. This preserves the original attack density: a DoS flood
        // at 1000 msg/s yields many more frames per tick than a spoofing attack.
        const atk = attackInjectionRef.current;
        if (atk && tickFrames.length) {
          const tickEndTs = tickFrames[tickFrames.length - 1].timestamp;
          while (atk.idx < atk.frames.length) {
            const adjTs = atk.frames[atk.idx].timestamp + atk.tsOffset;
            if (adjTs > tickEndTs + 0.1) break;
            tickFrames.push({ ...atk.frames[atk.idx], timestamp: adjTs });
            atk.idx++;
          }
          if (atk.idx >= atk.frames.length) {
            attackInjectionRef.current = null;
            setInjectionActive(false);
          }
          tickFrames.sort((a, b) => a.timestamp - b.timestamp);
        }
      }

      // Iterate frames, detect 200ms window boundaries, run detection pipeline
      const newlyVisible = [];

      for (const f of tickFrames) {
        newlyVisible.push(f);
        if (lastWinRef.current === null) lastWinRef.current = f.timestamp;

        // Extract BEFORE pushing f so the boundary-crossing frame starts the next
        // window rather than being pushed into a sub-window of its own. Without this,
        // extractWindowFeatures receives frames spanning 200ms+ε, creates a second
        // sub-window containing only the boundary frame, and gives it ratio=1.0.
        if (f.timestamp - lastWinRef.current >= WINDOW_MS / 1000) {
          const t0 = performance.now();
          const windowFrames = windowBufRef.current; // does NOT include f
          windowBufRef.current = [];
          lastWinRef.current = f.timestamp;

          const featRows = extractWindowFeatures(windowFrames, WINDOW_MS, baselineProfile, KNOWN_IDS);
          const newAttackers = new Set();
          let droppedFrames = 0;

          for (const row of featRows) {
            const score = scoreWindow(row, baselineStats);
            const attackType = score.isAnomaly ? classifyAttackType(row, baselineStats) : "Normal";
            const { action, incident } = engineRef.current.processWindowResult(row, score, attackType);

            if (action === "isolated" && incident) {
              handleIncident(incident);
              if (typeof incident.canId === "string" && !incident.canId.includes("distinct")) {
                newAttackers.add(incident.canId);
              }
            } else if (action === "isolated_aggregated" && incident) {
              // Fuzzy burst update: replace the existing log entry, don't append.
              handleFuzzyUpdate(incident);
            } else if (action === "dropped_isolated") {
              // Count the actual CAN frames being blocked from this isolated ID
              // (row.msgCount = frames from this ECU in this 200ms window).
              // This is what makes the counter rapidly increment during a flood.
              droppedFrames += row.msgCount || 1;
            }
          }

          if (droppedFrames > 0) setTotalFramesBlocked((prev) => prev + droppedFrames);
          setNetworkState(engineRef.current.getNetworkState(KNOWN_IDS));
          setMsgHistory((prev) => [...prev.slice(-39), windowFrames.length]);
          if (newAttackers.size) {
            setRecentAttackerIds(newAttackers);
            setTimeout(() => setRecentAttackerIds(new Set()), 900);
          }
          setLatencyMs(performance.now() - t0 + Math.random() * 0.4);
        }
        windowBufRef.current.push(f);
      }

      frameIdxRef.current = endIdx;
      setVisibleFrames((prev) => [...prev, ...newlyVisible].slice(-60));

      if (isNormal) {
        // Loop: wrap frame index and advance timestamp baseline so IATs remain
        // continuous across the seam (no backward-time jump).
        if (endIdx >= frames.length) {
          frameIdxRef.current = 0;
          normalTsOffsetRef.current += frames[frames.length - 1].timestamp - frames[0].timestamp + 0.05;
        }
        animRef.current = setTimeout(tick, 35);
      } else if (endIdx < frames.length) {
        animRef.current = setTimeout(tick, 35);
      } else {
        setIsPlaying(false);
      }
    }

    animRef.current = setTimeout(tick, 35);
    return () => clearTimeout(animRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isPlaying, liveMode, scenario, speed, loading, baselineProfile, baselineStats]);

  // ── Controls ───────────────────────────────────────────────────────────────
  const handleTogglePlay = useCallback(() => {
    if (liveMode) {
      if (!isPlaying) {
        resetSimulation();
        setIsPlaying(true);
        backend.connect(scenario, speed);
      } else {
        setIsPlaying(false);
        backend.pause();
      }
    } else {
      setIsPlaying((p) => !p);
    }
  }, [liveMode, isPlaying, scenario, speed, backend, resetSimulation]);

  const handleReset = useCallback(() => {
    pendingInjectionRef.current = null; // cancel any queued injection
    setIsPlaying(false);
    if (liveMode) backend.stop();
    resetSimulation();
  }, [liveMode, backend, resetSimulation]);

  const handleLiveModeToggle = useCallback(() => {
    setIsPlaying(false);
    if (liveMode) backend.disconnect();
    setLiveMode((v) => !v);
    resetSimulation();
  }, [liveMode, backend, resetSimulation]);

  const handleTopoDividerMouseDown = useCallback((e) => {
    e.preventDefault();
    const startY = e.clientY;
    const startH = topoHeightRef.current;
    const onMove = (ev) => {
      const next = Math.max(140, Math.min(600, startH + ev.clientY - startY));
      topoHeightRef.current = next;
      setTopoHeight(next);
    };
    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  }, []);

  const frames = scenarioFrames[scenario] || [];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", background: "var(--bg-void)" }}>
      {vignetteFlash && (
        <div style={{
          position: "fixed", inset: 0, pointerEvents: "none", zIndex: 9999,
          background: "radial-gradient(ellipse at center, transparent 35%, rgba(255,30,50,0.38) 100%)",
          boxShadow: "inset 0 0 140px rgba(255,30,50,0.55)",
          animation: "vignette-flash 0.85s ease-out forwards",
        }} />
      )}
      <StatusBar
        scenario={scenario}
        isPlaying={isPlaying}
        frameIdx={frameIdxRef.current}
        totalFrames={frames.length}
        latencyMs={latencyMs}
        msgHistory={msgHistory}
        alertEvent={alertEvent}
        liveMode={liveMode}
        backendConnected={backend.connected}
      />
      <ControlPanel
        scenario={scenario}
        onScenarioChange={(s) => { setIsPlaying(false); if (liveMode) backend.stop(); setScenario(s); }}
        isPlaying={isPlaying}
        onTogglePlay={handleTogglePlay}
        speed={speed}
        onSpeedChange={setSpeed}
        onReset={handleReset}
        loading={loading}
        liveMode={liveMode}
        onLiveModeToggle={handleLiveModeToggle}
        backendConnected={backend.connected}
        injectionActive={injectionActive}
        onInjectAttack={handleInjectAttack}
      />

      {backendError && (
        <div style={{
          padding: "8px 24px", background: "#1a1000",
          borderBottom: "1px solid var(--signal-amber)",
          fontSize: 11, color: "var(--signal-amber)", flexShrink: 0,
        }}>
          ⚠ Live mode: {backendError}
        </div>
      )}
      {modeNotice && (
        <div style={{
          padding: "6px 24px", background: "rgba(79,209,232,0.06)",
          borderBottom: "1px solid var(--signal-cyan-dim)",
          fontSize: 11, color: "var(--signal-cyan)", flexShrink: 0,
          display: "flex", alignItems: "center", gap: 8,
        }}>
          <span style={{ opacity: 0.7 }}>◈</span> {modeNotice}
        </div>
      )}
      <AlertBanner event={alertEvent} />

      <div style={{ flex: 1, display: "grid", gridTemplateColumns: "1fr clamp(280px, 28vw, 380px)", gap: 8, padding: 8, overflow: "hidden" }}>
        {/* Left column */}
        <div style={{ display: "flex", flexDirection: "column", gap: 8, minHeight: 0 }}>
          <div
            style={{
              background: "var(--bg-panel)", border: "1px solid var(--line)",
              borderRadius: "var(--radius)", padding: "8px 8px 4px",
              height: topoHeight, flexShrink: 0, overflow: "hidden",
            }}
          >
            <div style={{ fontSize: 9, fontWeight: 600, color: "var(--text-tertiary)", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 4 }}>
              Vehicle cyber digital twin
            </div>
            {loading ? (
              <div style={{ height: 280, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-tertiary)", fontSize: 12 }}>
                Loading CAN traffic…
              </div>
            ) : (
              <NetworkTopology networkState={networkState} recentAttackerIds={recentAttackerIds} />
            )}
          </div>

          {/* Drag handle */}
          <div
            onMouseDown={handleTopoDividerMouseDown}
            style={{
              flexShrink: 0, height: 8, cursor: "ns-resize",
              display: "flex", alignItems: "center", justifyContent: "center",
              margin: "-4px 0",  // overlap the gap so the hot-zone sits exactly on the seam
              zIndex: 10, position: "relative",
            }}
          >
            <div style={{
              width: 36, height: 3, borderRadius: 2,
              background: "var(--line-strong)",
              transition: "background 0.15s",
            }} />
          </div>

          <div style={{ flex: 1, minHeight: 0 }}>
            <TrafficFeed frames={visibleFrames} />
          </div>
        </div>

        {/* Right column */}
        <div style={{ display: "flex", flexDirection: "column", gap: 8, minHeight: 0 }}>
          <ThreatPanel
            alertEvent={alertEvent}
            totalFramesBlocked={totalFramesBlocked}
            networkState={networkState}
            liveMode={liveMode}
            modelType={backend.modelType}
          />
          {/* Explainability hero panel — shown when a detection is active.
              Reasons come from the live JS detector (scoreWindow), which
              mirrors detector.py explain() format. NOT hardcoded text. */}
          <ExplainPanel event={alertEvent} />
          <div style={{ flex: 1, minHeight: 0 }}>
            <IncidentLog incidents={incidents} />
          </div>
        </div>
      </div>
    </div>
  );
}
