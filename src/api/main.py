"""
AutoShield Edge AI — FastAPI Backend (Phase 5)
===============================================
Provides a WebSocket streaming endpoint and REST info endpoints so the React
dashboard can connect to real trained models instead of the JS port.

Run from inside src/:
  uvicorn api.main:app --reload --port 8001
  uvicorn api.main:app --port 8001 --data-dir ../data --model-dir ../models

WebSocket protocol:
  Client → Server (JSON):
    {"cmd": "start",  "scenario": "dos",  "speed": 10}
    {"cmd": "pause"}
    {"cmd": "resume"}
    {"cmd": "stop"}

  Server → Client (JSON):
    {"type": "status",       "state": "loading|ready|streaming|paused|done|error", ...}
    {"type": "ready",        "scenario": ..., "totalWindows": ..., "modelType": ...}
    {"type": "frame_batch",  "windowStart": ..., "frames": [...]}
    {"type": "window_result","windowStart": ..., "networkState": {...}, "incidents": [...], "latencyMs": ...}
    {"type": "done",         "scenario": ...}
    {"type": "error",        "message": ...}

REST endpoints:
  GET /api/health      — {"status":"ok", "models_ready":true, "model_type":"Ensemble"}
  GET /api/model-info  — detailed model metadata
  GET /api/scenarios   — list of available scenarios with file existence check
"""

import asyncio
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from api.streamer import AutoShieldStreamer

# Resolve paths relative to src/
_SRC = os.path.dirname(os.path.dirname(__file__))
DATA_DIR  = os.environ.get("AUTOSHIELD_DATA_DIR",  os.path.join(_SRC, "../data"))
MODEL_DIR = os.environ.get("AUTOSHIELD_MODEL_DIR", os.path.join(_SRC, "../models"))

streamer = AutoShieldStreamer(data_dir=DATA_DIR, model_dir=MODEL_DIR)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load models once at startup (runs in thread pool to avoid blocking)
    print("AutoShield API starting — loading models…")
    loop = asyncio.get_running_loop()
    msg = await loop.run_in_executor(None, streamer.load_models)
    print(f"  Model: {msg}")
    yield
    # Cleanup (nothing needed currently)


app = FastAPI(
    title="AutoShield Edge AI API",
    description="CAN bus intrusion detection — real-time streaming endpoint",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # Dashboard can be on any port during development
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── REST endpoints ────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status":       "ok",
        "models_ready": streamer.models_ready,
        "model_type":   streamer.model_type,
    }


@app.get("/api/model-info")
async def model_info():
    return streamer.get_model_info()


@app.get("/api/scenarios")
async def scenarios():
    result = {}
    for mode in ["normal", "dos", "fuzzy", "spoof"]:
        path = os.path.join(DATA_DIR, f"can_{mode}.csv")
        result[mode] = {
            "available": os.path.exists(path),
            "path": path,
        }
    return result


# ── WebSocket streaming endpoint ──────────────────────────────────────────────

@app.websocket("/ws/stream")
async def websocket_stream(ws: WebSocket):
    await ws.accept()

    stop_event  = asyncio.Event()
    pause_event = asyncio.Event()
    stream_task: asyncio.Task | None = None

    async def send(msg: dict):
        try:
            await ws.send_json(msg)
        except Exception:
            stop_event.set()

    try:
        while True:
            data = await ws.receive_json()
            cmd = data.get("cmd", "")

            if cmd == "start":
                # Cancel any active stream before starting a new one
                if stream_task and not stream_task.done():
                    stop_event.set()
                    await asyncio.gather(stream_task, return_exceptions=True)

                stop_event.clear()
                pause_event.clear()

                scenario = data.get("scenario", "dos")
                speed    = max(1, min(int(data.get("speed", 10)), 200))

                # Run the streaming loop as a background task so we can
                # concurrently receive pause/stop commands from the client
                async def run_stream():
                    try:
                        await streamer.stream_scenario(scenario, speed, send, stop_event, pause_event)
                    except Exception as e:
                        stop_event.set()
                        await send({"type": "error", "message": f"Server crash: {str(e)}"})

                stream_task = asyncio.create_task(run_stream())

            elif cmd == "pause":
                pause_event.set()
                await send({"type": "status", "state": "paused"})

            elif cmd == "resume":
                pause_event.clear()
                await send({"type": "status", "state": "streaming"})

            elif cmd == "stop":
                stop_event.set()
                if stream_task:
                    await asyncio.gather(stream_task, return_exceptions=True)
                await send({"type": "status", "state": "stopped"})

    except (WebSocketDisconnect, RuntimeError):
        stop_event.set()
        if stream_task and not stream_task.done():
            stream_task.cancel()
