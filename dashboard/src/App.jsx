import { useCallback, useEffect, useMemo, useState } from "react";
import { fetchState, control } from "./lib/api";
import StatusBar from "./components/StatusBar";
import ControlPanel from "./components/ControlPanel";
import NetworkTopology from "./components/NetworkTopology";
import TrafficFeed from "./components/TrafficFeed";
import IncidentLog from "./components/IncidentLog";

const EMPTY_STATE = {
  scenario: "normal",
  running: false,
  step: 0,
  events: [],
  incidents: [],
  networkState: {},
  model: "AutoShield Hybrid-v4",
};

export default function App() {
  const [state, setState] = useState(EMPTY_STATE);
  const [backendOnline, setBackendOnline] = useState(false);
  const [everConnected, setEverConnected] = useState(false);
  const [commandError, setCommandError] = useState("");

  useEffect(() => {
    let cancelled = false;
    let timer;

    async function poll() {
      try {
        const next = await fetchState();
        if (cancelled) return;
        setState(next);
        setBackendOnline(true);
        setEverConnected(true);
      } catch {
        if (!cancelled) setBackendOnline(false);
      } finally {
        if (!cancelled) timer = setTimeout(poll, 300);
      }
    }

    poll();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, []);

  const send = useCallback(async (action, scenario = state.scenario) => {
    setCommandError("");
    try {
      const result = await control(action, scenario);
      if (result.state) setState(result.state);
      setBackendOnline(true);
    } catch (err) {
      setBackendOnline(false);
      setCommandError(err.message);
    }
  }, [state.scenario]);

  const latestEvent = state.events.length ? state.events[state.events.length - 1] : null;
  const visibleFrames = useMemo(() => state.events.map((e) => e.frame), [state.events]);
  const recentAttackerIds = useMemo(() => {
    const ids = new Set();
    if (latestEvent?.evidence?.alert && latestEvent.evidence.can_id) ids.add(latestEvent.evidence.can_id);
    return ids;
  }, [latestEvent]);

  const latencyMs = latestEvent?.inference_ms ?? 0;
  const statusText = backendOnline ? "CONNECTED" : everConnected ? "RECONNECTING" : "CONNECTING";
  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh" }}>
      <StatusBar
        scenario={state.scenario}
        isPlaying={state.running}
        frameIdx={state.step}
        latencyMs={latencyMs}
        backendOnline={backendOnline}
        connectionText={statusText}
        model={state.model}
      />
      <ControlPanel
        scenario={state.scenario}
        onScenarioChange={(scenario) => send("scenario", scenario)}
        isPlaying={state.running}
        onTogglePlay={() => send(state.running ? "stop" : "start", state.scenario)}
        speed={10}
        onSpeedChange={() => {}}
        onReset={() => send("reset", state.scenario)}
        loading={!backendOnline}
      />

      {commandError && (
        <div style={{ padding: "6px 24px", background: "var(--signal-red-dim)", color: "var(--signal-red)", fontSize: 11 }}>
          Backend command failed: {commandError}
        </div>
      )}

      <div style={{ flex: 1, display: "grid", gridTemplateColumns: "1fr 400px", gap: 16, padding: 16, overflow: "hidden" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 16, minHeight: 0 }}>
          <div style={{
            background: "var(--bg-panel)",
            border: "1px solid var(--line)",
            borderRadius: "var(--radius)",
            padding: 16,
            flex: "0 0 auto",
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                Vehicle cyber digital twin
              </div>
              <div className="mono" style={{ fontSize: 10, color: "var(--signal-cyan)" }}>
                evidence source: {state.model}
              </div>
            </div>
            <NetworkTopology networkState={state.networkState || {}} recentAttackerIds={recentAttackerIds} />
          </div>
          <div style={{ flex: 1, minHeight: 0 }}>
            <TrafficFeed frames={visibleFrames} />
          </div>
        </div>
        <div style={{ minHeight: 0 }}>
          <IncidentLog incidents={state.incidents || []} />
        </div>
      </div>
    </div>
  );
}
