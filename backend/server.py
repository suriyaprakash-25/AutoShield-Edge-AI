from __future__ import annotations
import argparse
import json
import mimetypes
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from simulator import DemoSimulator, SCENARIOS

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dashboard" / "dist"
SIM = DemoSimulator()
STOP = threading.Event()

def simulation_loop():
    while not STOP.is_set():
        if SIM.running:
            SIM.tick()
        STOP.wait(0.25)

class Handler(BaseHTTPRequestHandler):
    server_version = "AutoShieldDemo/4.0"

    def log_message(self, fmt, *args):
        print(f"[http] {self.address_string()} - {fmt % args}", flush=True)

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            return self._json(200, {
                "status": "ok",
                "service": "AutoShield Stage-2 POC",
                "model": "AutoShield Hybrid-v4",
                "schema": 4,
            })
        if path == "/api/scenarios":
            return self._json(200, {"scenarios": SCENARIOS})
        if path == "/api/state":
            return self._json(200, SIM.snapshot())
        self._serve_static(path)

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/control":
            return self._json(404, {"error": "not found"})
        try:
            payload = self._read_json()
            action = payload.get("action")
            scenario = payload.get("scenario")
            if action == "start":
                SIM.start(scenario)
            elif action == "stop":
                SIM.stop()
            elif action == "reset":
                SIM.reset(scenario)
            elif action == "scenario":
                SIM.set_scenario(scenario)
            else:
                return self._json(400, {"error": f"unsupported action: {action}"})
            return self._json(200, {"ok": True, "state": SIM.snapshot()})
        except (ValueError, json.JSONDecodeError) as exc:
            return self._json(400, {"error": str(exc)})
    def _serve_static(self, path: str):
        if not DIST.exists():
            return self._json(503, {
                "error": "dashboard build not found",
                "hint": "cd dashboard && npm run build",
            })
        rel = path.lstrip("/") or "index.html"
        candidate = (DIST / rel).resolve()
        if DIST.resolve() not in candidate.parents and candidate != DIST.resolve():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not candidate.is_file():
            candidate = DIST / "index.html"
        try:
            body = candidate.read_bytes()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type, _ = mimetypes.guess_type(str(candidate))
        self.send_response(200)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache" if candidate.name == "index.html" else "public, max-age=3600")
        self.end_headers()
        self.wfile.write(body)

def main():
    parser = argparse.ArgumentParser(description="AutoShield Stage-2 POC backend + static dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    thread = threading.Thread(target=simulation_loop, daemon=True)
    thread.start()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"AutoShield Hybrid-v4 POC listening on http://{args.host}:{args.port}", flush=True)
    print("Scenarios: normal, dos, fuzzy, rpm, gear", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        STOP.set()
        server.server_close()
        thread.join(timeout=1)

if __name__ == "__main__":
    main()
