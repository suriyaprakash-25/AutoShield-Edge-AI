/**
 * useBackend — WebSocket client hook for AutoShield live backend mode
 *
 * Connects to the FastAPI WebSocket at ws://localhost:8001/ws/stream.
 * Exposes connect/pause/resume/stop controls and calls props callbacks
 * for every streaming message from the server.
 *
 * When the backend is unreachable the hook fires onError so the UI can
 * gracefully fall back to demo mode (JS detection).
 */

import { useCallback, useEffect, useRef, useState } from "react";

const WS_URL = "ws://localhost:8001/ws/stream";

export default function useBackend({
  onFrameBatch,     // (frames: Frame[]) => void
  onWindowResult,   // ({ windowStart, networkState, incidents, latencyMs }) => void
  onStatusChange,   // (state: string) => void
  onError,          // (message: string) => void
}) {
  const ws = useRef(null);
  const [connected, setConnected] = useState(false);
  const [modelType, setModelType] = useState(null);
  const [backendReady, setBackendReady] = useState(false);

  // Stable refs so callbacks don't force re-connection
  const cbRef = useRef({ onFrameBatch, onWindowResult, onStatusChange, onError });
  useEffect(() => {
    cbRef.current = { onFrameBatch, onWindowResult, onStatusChange, onError };
  });

  // ── Connection ─────────────────────────────────────────────────────────────

  const connect = useCallback((scenario, speed) => {
    // Close any existing connection
    if (ws.current) {
      ws.current.onclose = null;
      ws.current.close();
    }

    const socket = new WebSocket(WS_URL);
    ws.current = socket;

    socket.onopen = () => {
      setConnected(true);
      socket.send(JSON.stringify({ cmd: "start", scenario, speed }));
    };

    socket.onmessage = (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }

      switch (msg.type) {
        case "ready":
          setModelType(msg.modelType || null);
          setBackendReady(true);
          cbRef.current.onStatusChange?.("streaming");
          break;

        case "frame_batch":
          cbRef.current.onFrameBatch?.(msg.frames || []);
          break;

        case "window_result":
          cbRef.current.onWindowResult?.(msg);
          break;

        case "status":
          cbRef.current.onStatusChange?.(msg.state);
          break;

        case "done":
          cbRef.current.onStatusChange?.("done");
          break;

        case "error":
          cbRef.current.onError?.(msg.message || "Backend error");
          break;
      }
    };

    socket.onerror = () => {
      cbRef.current.onError?.("Cannot connect to backend — is uvicorn running on port 8001?");
    };

    socket.onclose = () => {
      setConnected(false);
      setBackendReady(false);
    };
  }, []);

  const send = useCallback((cmd) => {
    if (ws.current?.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(cmd));
    }
  }, []);

  const pause  = useCallback(() => send({ cmd: "pause" }),  [send]);
  const resume = useCallback(() => send({ cmd: "resume" }), [send]);

  const stop = useCallback(() => {
    send({ cmd: "stop" });
    setBackendReady(false);
  }, [send]);

  const disconnect = useCallback(() => {
    if (ws.current) {
      ws.current.onclose = null;
      ws.current.onerror = null; // prevent spurious error callbacks on intentional close
      ws.current.close();
      ws.current = null;
    }
    setConnected(false);
    setBackendReady(false);
  }, []);

  // Cleanup on unmount
  useEffect(() => () => disconnect(), [disconnect]);

  return { connected, backendReady, modelType, connect, pause, resume, stop, disconnect, send };
}
