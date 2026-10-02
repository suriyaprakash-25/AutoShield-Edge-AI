import json
import socket
import subprocess
import sys
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "backend" / "server.py"

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

class PhaseGIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.port = free_port()
        self.proc = None
        self.start_server()

    def tearDown(self):
        self.stop_server()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"

    def start_server(self):
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER), "--port", str(self.port)],
            cwd=str(ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(self.base + "/api/health", timeout=0.5) as response:
                    if response.status == 200:
                        return
            except Exception:
                time.sleep(0.1)
        self.fail("backend did not become healthy")

    def stop_server(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)

    def post(self, payload):
        req = urllib.request.Request(
            self.base + "/api/control",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2) as response:
            return json.loads(response.read().decode())

    def state(self):
        with urllib.request.urlopen(self.base + "/api/state", timeout=2) as response:
            return json.loads(response.read().decode())

    def test_full_pipeline_api(self):
        self.post({"action": "scenario", "scenario": "gear"})
        self.post({"action": "start", "scenario": "gear"})
        time.sleep(0.55)
        state = self.state()
        self.assertTrue(state["running"])
        self.assertGreaterEqual(len(state["events"]), 1)
        self.assertGreaterEqual(len(state["incidents"]), 1)
        self.assertIn("ML_GEAR", state["incidents"][-1]["reasonCodes"])
        self.post({"action": "stop", "scenario": "gear"})
        self.assertFalse(self.state()["running"])

    def test_mix_pipeline_contains_all_four_vectors(self):
        self.post({"action": "scenario", "scenario": "mix"})
        self.post({"action": "start", "scenario": "mix"})
        time.sleep(1.15)
        state = self.state()
        self.post({"action": "stop", "scenario": "mix"})
        reasons = {
            reason
            for incident in state["incidents"]
            for reason in incident["reasonCodes"]
        }
        self.assertTrue({
            "RATE_LIMIT_EXCEEDED", "UNKNOWN_ID", "ML_RPM", "ML_GEAR"
        }.issubset(reasons))
        self.assertGreaterEqual(len(state["incidents"]), 4)

    def test_backend_restart_reconnects(self):
        health_before = json.loads(urllib.request.urlopen(self.base + "/api/health").read().decode())
        self.assertEqual(health_before["status"], "ok")
        self.stop_server()
        with self.assertRaises(Exception):
            urllib.request.urlopen(self.base + "/api/health", timeout=0.4)
        self.start_server()
        health_after = json.loads(urllib.request.urlopen(self.base + "/api/health").read().decode())
        self.assertEqual(health_after["model"], "AutoShield Hybrid-v4")

if __name__ == "__main__":
    unittest.main()
