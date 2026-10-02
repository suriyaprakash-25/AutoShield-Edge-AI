from __future__ import annotations
import math
import random
import threading
import time
from typing import Dict, List

from hybrid_v4_model import HybridV4Detector

SCENARIOS = {
    "normal": {"label": "Normal", "description": "Commissioned CAN traffic, no attack"},
    "dos": {"label": "DoS", "description": "High-rate traffic violates the per-ID 100 ms rate policy"},
    "fuzzy": {"label": "Fuzzy", "description": "Uncommissioned random CAN IDs are injected"},
    "rpm": {"label": "RPM spoof", "description": "0x316 stays within structural policy but triggers the RPM ML specialist"},
    "gear": {"label": "Gear spoof", "description": "0x43F stays within structural policy but triggers the Gear ML specialist"},
}

class DemoSimulator:
    def __init__(self):
        self.detector = HybridV4Detector()
        self.lock = threading.RLock()
        self.scenario = "normal"
        self.running = False
        self.step = 0
        self.events: List[dict] = []
        self.incidents: List[dict] = []
        self.generation = 0
        self._rpm_attack = self.detector.specialists[0x316].attack_prototype()
        self._gear_attack = self.detector.specialists[0x43F].attack_prototype()
        self.reset("normal")

    def _payload(self, seed: int, can_id: int, features: Dict[str, float] | None = None) -> List[str]:
        if features:
            out = []
            for i in range(8):
                mean = max(0.0, min(1.0, float(features.get(f"b{i}_mean", 0.25))))
                out.append(f"{int(round(mean * 255)):02X}")
            return out
        rng = random.Random(seed * 10000 + can_id)
        return [f"{rng.randrange(0, 256):02X}" for _ in range(8)]
    def _sample(self) -> dict:
        t = self.step * 0.1
        normal_ids = [0x130, 0x131, 0x140, 0x153, 0x18F, 0x1F1, 0x260, 0x4B1]
        scenario = self.scenario
        features = None
        flag = "R"

        if scenario == "normal":
            can_id = normal_ids[self.step % len(normal_ids)]
            count = max(1, min(5, self.detector.rate_limit[can_id] - 1))
            dlc_mean = 1.0
        elif scenario == "dos":
            can_id = 0x130
            count = self.detector.rate_limit[can_id] + 20
            dlc_mean = 1.0
            flag = "T"
        elif scenario == "fuzzy":
            can_id = 0x555 + (self.step % 8)
            count = 2
            dlc_mean = 1.0
            flag = "T"
        elif scenario == "rpm":
            can_id = 0x316
            count = min(10, self.detector.rate_limit[can_id])
            dlc_mean = 1.0
            features = dict(self._rpm_attack)
            flag = "T"
        elif scenario == "gear":
            can_id = 0x43F
            count = min(10, self.detector.rate_limit[can_id])
            dlc_mean = 1.0
            features = dict(self._gear_attack)
            flag = "T"
        else:
            raise ValueError(f"Unknown scenario: {scenario}")
        if features is None:
            features = {}
        features.setdefault("log_count", math.log1p(count))
        features.setdefault("log_bus_count", math.log1p(max(count + 35, 1)))
        features.setdefault("bus_ids", 24.0)
        features.setdefault("iat_mean", 0.08)
        features.setdefault("iat_std", 0.01)
        features["dlc_mean"] = dlc_mean
        features["dlc_std"] = 0.0

        return {
            "id": can_id,
            "count": count,
            "dlc_mean": dlc_mean,
            "features": features,
            "frame": {
                "timestamp": round(t, 3),
                "canId": f"{can_id:04X}",
                "dlc": 8,
                "dataBytes": self._payload(self.step, can_id, features if scenario in ("rpm", "gear") else None),
                "flag": flag,
            },
        }

    def tick(self) -> dict:
        with self.lock:
            sample = self._sample()
            started = time.perf_counter_ns()
            evidence = self.detector.evaluate(sample)
            inference_ms = (time.perf_counter_ns() - started) / 1e6
            event = {
                "sequence": self.step,
                "scenario": self.scenario,
                "frame": sample["frame"],
                "evidence": evidence,
                "inference_ms": inference_ms,
            }
            self.events.append(event)
            self.events = self.events[-80:]
            if evidence["alert"]:
                incident = {
                    "id": f"INC-{self.generation:02d}-{self.step:04d}",
                    "windowStart": sample["frame"]["timestamp"],
                    "canId": evidence["can_id"],
                    "attackType": SCENARIOS[self.scenario]["label"],
                    "confidence": evidence["confidence"],
                    "reasons": [x["detail"] for x in evidence["evidence"]],
                    "reasonCodes": evidence["reasons"],
                    "actionTaken": evidence["action"],
                    "mlScores": evidence["ml_scores"],
                    "model": evidence["model"],
                }
                self.incidents.append(incident)
                self.incidents = self.incidents[-40:]
                event["incident"] = incident
            self.step += 1
            return event

    def start(self, scenario: str | None = None) -> None:
        with self.lock:
            if scenario:
                self.set_scenario(scenario)
            self.running = True

    def stop(self) -> None:
        with self.lock:
            self.running = False

    def set_scenario(self, scenario: str) -> None:
        if scenario not in SCENARIOS:
            raise ValueError(f"Unknown scenario {scenario}")
        with self.lock:
            if scenario != self.scenario:
                self.reset(scenario)

    def reset(self, scenario: str | None = None) -> None:
        with self.lock:
            if scenario:
                if scenario not in SCENARIOS:
                    raise ValueError(f"Unknown scenario {scenario}")
                self.scenario = scenario
            self.running = False
            self.step = 0
            self.events = []
            self.incidents = []
            self.generation += 1

    def snapshot(self) -> dict:
        with self.lock:
            network = {}
            for cid in ["0316", "018F", "0260", "02A0", "0329", "0153", "043F", "05A0", "0220", "04B1"]:
                network[cid] = "normal"
            if self.events:
                ev = self.events[-1]
                if ev["evidence"]["alert"]:
                    cid = ev["evidence"]["can_id"]
                    if cid in network:
                        network[cid] = "isolated" if ev["evidence"]["action"] == "DROP" else "suspicious"
            return {
                "scenario": self.scenario,
                "scenarioMeta": SCENARIOS[self.scenario],
                "running": self.running,
                "step": self.step,
                "events": list(self.events),
                "incidents": list(self.incidents),
                "networkState": network,
                "model": "AutoShield Hybrid-v4",
                "generation": self.generation,
            }
