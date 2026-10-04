from __future__ import annotations
import json
import math
from pathlib import Path
from typing import Any, Dict

MODEL_DIR = Path(__file__).resolve().parent / "model"

def _load_json(name: str) -> dict:
    with (MODEL_DIR / name).open("r", encoding="utf-8") as f:
        return json.load(f)

class Specialist:
    def __init__(self, artifact: dict):
        self.name = artifact["name"]
        self.target_id = int(artifact["target_id"])
        self.features = list(artifact["features"])
        self.mean = [float(x) for x in artifact["mean"]]
        self.scale = [float(x) if float(x) != 0 else 1.0 for x in artifact["scale"]]
        self.coef = [float(x) for x in artifact["coef"]]
        self.intercept = float(artifact["intercept"])
        self.threshold = float(artifact["probability_threshold"])

    def probability(self, features: Dict[str, float]) -> float:
        z = self.intercept
        for i, feature in enumerate(self.features):
            value = float(features.get(feature, self.mean[i]))
            standardized = (value - self.mean[i]) / self.scale[i]
            z += standardized * self.coef[i]
        z = max(-60.0, min(60.0, z))
        return 1.0 / (1.0 + math.exp(-z))
    def attack_prototype(self, target_margin: float = 0.03) -> Dict[str, float]:
        target = min(0.999, self.threshold + target_margin)
        factor = 0.20
        while factor <= 2.0:
            values = {}
            for i, feature in enumerate(self.features):
                direction = 1.0 if self.coef[i] >= 0 else -1.0
                values[feature] = self.mean[i] + factor * direction * self.scale[i]
            values["dlc_mean"] = 1.0
            values["dlc_std"] = 0.0
            if self.probability(values) >= target:
                return values
            factor += 0.05
        return values

class HybridV4Detector:
    def __init__(self):
        self.policy = _load_json("hybrid_policy.json")
        self.allowlist = {int(x) for x in self.policy["allowlist"]}
        self.rate_limit = {int(k): int(v) for k, v in self.policy["rate_limit_count_per_100ms"].items()}
        self.dlc_range = {int(k): (float(v[0]), float(v[1])) for k, v in self.policy["dlc_mean_range"].items()}
        self.specialists = {}
        for filename in self.policy["specialist_files"]:
            spec = Specialist(_load_json(filename))
            self.specialists[spec.target_id] = spec

    def evaluate(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        can_id = int(sample["id"])
        count = int(sample["count"])
        dlc_mean = float(sample["dlc_mean"])
        features = dict(sample.get("features") or {})
        reasons = []
        evidence = []
        if can_id not in self.allowlist:
            reasons.append("UNKNOWN_ID")
            evidence.append({"type": "rule", "name": "allowlist", "detail": f"0x{can_id:03X} not in commissioned allowlist"})
        else:
            if count > self.rate_limit[can_id]:
                reasons.append("RATE_LIMIT_EXCEEDED")
                evidence.append({"type": "rule", "name": "rate", "detail": f"{count} > {self.rate_limit[can_id]} frames/100ms"})
            lo, hi = self.dlc_range[can_id]
            if not (lo <= dlc_mean <= hi):
                reasons.append("DLC_POLICY_VIOLATION")
                evidence.append({"type": "rule", "name": "dlc", "detail": f"normalized DLC {dlc_mean:.3f} outside [{lo:.3f}, {hi:.3f}]"})

        ml_scores = {}
        specialist = self.specialists.get(can_id)
        if specialist is not None:
            score = specialist.probability(features)
            ml_scores[specialist.name] = {
                "probability": score,
                "threshold": specialist.threshold,
                "triggered": score > specialist.threshold,
            }
            if score > specialist.threshold:
                reason = f"ML_{specialist.name.upper()}"
                reasons.append(reason)
                evidence.append({"type": "ml", "name": specialist.name, "detail": f"p={score:.6f} > threshold={specialist.threshold:.6f}"})

        action = "ALLOW"
        if "RATE_LIMIT_EXCEEDED" in reasons:
            action = "RATE_LIMIT"
        if "UNKNOWN_ID" in reasons or "DLC_POLICY_VIOLATION" in reasons:
            action = "DROP"
        if any(r.startswith("ML_") for r in reasons) and action == "ALLOW":
            action = "ALERT"

        confidence = 0.0
        if ml_scores:
            confidence = max(x["probability"] for x in ml_scores.values())
        if any(r in reasons for r in ("UNKNOWN_ID", "RATE_LIMIT_EXCEEDED", "DLC_POLICY_VIOLATION")):
            confidence = max(confidence, 0.99)

        return {
            "alert": bool(reasons),
            "can_id": f"{can_id:04X}",
            "reasons": reasons,
            "evidence": evidence,
            "ml_scores": ml_scores,
            "action": action,
            "confidence": confidence,
            "model": "AutoShield Hybrid-v4",
            "window_ms": int(float(self.policy["window_seconds"]) * 1000),
        }
