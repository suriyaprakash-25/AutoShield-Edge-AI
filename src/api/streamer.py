"""
AutoShield Edge AI — Streaming Detection Pipeline
==================================================
AutoShieldStreamer: loads models once, then streams window-by-window detection
results over any async send-function (used by the WebSocket handler in main.py).

Flow per scenario:
  1. Load CSV upfront (< 1MB, fast)
  2. Extract all window features (needed for cross-window IAT correctness)
  3. Init LSTM streaming buffers
  4. Iterate windows, run ensemble per window, emit JSON via send_fn
  5. Between windows: yield to asyncio event loop so WebSocket messages land
"""

import asyncio
import os
import sys
import time
import threading
from typing import Callable, Awaitable

import pandas as pd

# Resolve src/ package root so imports work when launched from api/
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from feature_extraction import build_baseline_profile, extract_window_features, load_can_csv
from response_engine import ResponseEngine
from ensemble_detector import EnsembleDetector
from lstm_detector import LSTMAnomalyDetector
from detector import CANAnomalyDetector

WINDOW_MS = 200


def _frames_to_json(df: pd.DataFrame) -> list[dict]:
    """Convert a window's raw frame slice to a JSON-serialisable list."""
    records = []
    for _, row in df.iterrows():
        records.append({
            "timestamp": round(float(row["Timestamp"]), 6),
            "canId":     str(row["CAN_ID"]),
            "dlc":       int(row.get("DLC", 8)),
            "dataBytes": [str(row.get(f"DATA{i}", "00")) for i in range(8)],
            "flag":      str(row.get("Flag", "R")),
        })
    return records


class AutoShieldStreamer:
    """Singleton-like service — constructed once at API startup, reused per WebSocket session."""

    def __init__(self, data_dir: str = "../data", model_dir: str = "../models"):
        self.data_dir = data_dir
        self.model_dir = model_dir
        self.detector = None
        self.model_type: str = "none"
        self.profile: dict = {}
        self.known_ids: set = set()
        self.normal_id_ratio: dict = {}   # per-ID mean msg_count_ratio from normal traffic
        self.models_ready: bool = False
        self._scenario_cache: dict[str, tuple] = {}   # scenario → (all_features, frames_df)

    # ── Model loading ────────────────────────────────────────────────────────

    def load_models(self) -> str:
        """
        Load best available trained model. Preference: ensemble > lstm > iso.
        Loads baseline profile from can_normal.csv.
        Returns human-readable model type string.
        """
        normal_path = f"{self.data_dir}/can_normal.csv"
        if not os.path.exists(normal_path):
            return "ERROR: can_normal.csv not found — run generate_dataset.py first"

        df_normal = load_can_csv(normal_path)
        self.profile, self.known_ids = build_baseline_profile(df_normal)

        # Compute per-ID baseline msg_count_ratio — same groupby used in the
        # validated test scripts (full_re_test_attributed.py) that produced the
        # 763→3 DoS false-positive result.  Stored once so every streaming
        # session uses the same ratio dict without recomputing per scenario.
        feat_normal = extract_window_features(df_normal, WINDOW_MS, self.profile, self.known_ids)
        self.normal_id_ratio = feat_normal.groupby("CAN_ID")["msg_count_ratio"].mean().to_dict()

        # IsoForest baseline is the validated demo model:
        #   DoS F1=0.5634, Fuzzy F1=0.9834, Spoof F1=0.6012
        # The Ensemble (IsoForest + LSTM-AE) was evaluated and rejected:
        #   DoS F1=0.45, Spoof F1=0.20 — worse across the board.
        # Do NOT change this back to a fallback chain without re-evaluating.
        iso_meta = f"{self.model_dir}/can_isoforest_baseline_meta.json"
        if os.path.exists(iso_meta):
            self.detector = CANAnomalyDetector.load(f"{self.model_dir}/can_isoforest_baseline")
            self.model_type = "IsolationForest"
            self.models_ready = True
            # Prewarm in a daemon thread so the server comes up immediately.
            # The first WebSocket request for any scenario will use the cache
            # if prewarming finished, otherwise it extracts features on-demand.
            t = threading.Thread(target=self._prewarm_scenarios, daemon=True)
            t.start()
            return self.model_type

        return "ERROR: can_isoforest_baseline model not found — run train_baseline.py first"

    def _prewarm_scenarios(self) -> None:
        """Pre-extract features for all attack scenarios at startup so the first
        WebSocket request is instant rather than blocking for minutes on Fuzzy."""
        for mode in ["dos", "fuzzy", "spoof"]:
            if mode not in self._scenario_cache:
                result = self._load_scenario(mode)
                if result:
                    print(f"  Pre-warmed: {mode} ({len(result[0]):,} feature rows)")

    def get_model_info(self) -> dict:
        return {
            "type":        self.model_type,
            "ready":       self.models_ready,
            "known_ids":   sorted(self.known_ids),
            "n_known_ids": len(self.known_ids),
        }

    # ── Scenario pre-processing ──────────────────────────────────────────────

    def _load_scenario(self, scenario: str) -> tuple | None:
        """Return (all_features_df, frames_df) for scenario, with in-memory cache."""
        if scenario in self._scenario_cache:
            return self._scenario_cache[scenario]

        path = f"{self.data_dir}/can_{scenario}.csv"
        if not os.path.exists(path):
            return None

        frames = load_can_csv(path)
        features = extract_window_features(frames, WINDOW_MS, self.profile, self.known_ids)
        self._scenario_cache[scenario] = (features, frames)
        return features, frames

    # ── Main streaming loop ──────────────────────────────────────────────────

    async def stream_scenario(
        self,
        scenario: str,
        speed: int,
        send_fn: Callable[[dict], Awaitable[None]],
        stop_event: asyncio.Event,
        pause_event: asyncio.Event,
    ) -> None:
        """
        Stream all windows for `scenario` over `send_fn`.

        Message types emitted:
          status       — loading/ready/done/error state changes
          frame_batch  — raw CAN frames for the current window (for TrafficFeed)
          window_result — detection results + network state (for topology + incident log)
        """
        if not self.models_ready:
            await send_fn({"type": "error", "message": "Models not loaded — run train_ensemble.py"})
            return

        # ── Load + pre-process ────────────────────────────────────────────────
        await send_fn({"type": "status", "state": "loading", "scenario": scenario})
        # Run in thread executor — feature extraction is CPU-bound (pandas/numpy)
        # and would block the asyncio event loop, causing the WebSocket to drop.
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._load_scenario, scenario)
        if result is None:
            await send_fn({"type": "error", "message": f"Dataset not found: can_{scenario}.csv"})
            return

        all_features, frames_df = result
        windows = sorted(all_features["window_start"].unique())

        await send_fn({
            "type":          "ready",
            "scenario":      scenario,
            "totalWindows":  len(windows),
            "totalFrames":   len(frames_df),
            "modelType":     self.model_type,
        })

        # ── Streaming state ───────────────────────────────────────────────────
        engine = ResponseEngine(
            normal_id_ratio=self.normal_id_ratio,
            attribution_ratio_mult=3.0,
        )
        if hasattr(self.detector, "init_stream"):
            self.detector.init_stream()

        window_s = WINDOW_MS / 1000.0
        sleep_s  = max(0.004, 0.035 / max(speed, 1))  # ~35ms at speed=1, faster at higher speed

        # ── Window-by-window loop ─────────────────────────────────────────────
        for window_start in windows:
            if stop_event.is_set():
                break

            while pause_event.is_set() and not stop_event.is_set():
                await asyncio.sleep(0.05)

            w_end = window_start + window_s
            w_feats = all_features[all_features["window_start"] == window_start]
            w_frames = frames_df[
                (frames_df["Timestamp"] >= window_start) & (frames_df["Timestamp"] < w_end)
            ]

            # ── Per-window detection ──────────────────────────────────────────
            t0 = time.perf_counter()
            incidents_out = []
            dropped_frames = 0  # CAN frames suppressed from isolated ECUs this window

            for _, row in w_feats.iterrows():
                can_id = str(row["CAN_ID"])

                if hasattr(self.detector, "predict_stream_row"):
                    # Ensemble / LSTM streaming
                    conf, is_anom, iso_c, lstm_c = self.detector.predict_stream_row(can_id, row)
                    row = row.copy()
                    row["is_anomaly"]   = is_anom
                    row["confidence"]   = conf
                    row["anomaly_score"] = conf
                else:
                    # IsoForest fallback: single-row batch predict
                    tmp = pd.DataFrame([row.to_dict()])
                    res = self.detector.predict(tmp)
                    row = res.iloc[0]
                    is_anom = int(row["is_anomaly"])

                if is_anom:
                    explanation  = self.detector.explain(row)
                    attack_type  = self.detector.classify_attack_type(row)
                else:
                    explanation  = {"reasons": [], "is_severe": False, "bus_under_congestion": False, "max_abs_zscore": 0}
                    attack_type  = "Normal"

                action, incident = engine.process_window_result(row, explanation, attack_type)
                if action == "dropped_isolated":
                    # Count the actual CAN frames blocked from this isolated ECU.
                    # msg_count = frames from this ID in this 200ms window.
                    dropped_frames += int(row.get("msg_count", 1))
                elif incident:
                    incidents_out.append({
                        # Match the JS incident shape expected by the dashboard
                        "id":          incident.incident_id,
                        "timestamp":   incident.timestamp,
                        "canId":       incident.can_id,
                        "attackType":  incident.attack_type,
                        "confidence":  incident.confidence,
                        "reasons":     incident.reasons,
                        "actionTaken": incident.action_taken,
                        "windowStart": incident.window_start,
                    })

            network_state = engine.get_network_state(self.known_ids)
            latency_ms = (time.perf_counter() - t0) * 1000

            # ── Emit ──────────────────────────────────────────────────────────
            await send_fn({
                "type":         "frame_batch",
                "windowStart":  window_start,
                "frames":       _frames_to_json(w_frames),
            })
            await send_fn({
                "type":          "window_result",
                "windowStart":   window_start,
                "networkState":  {k: v for k, v in network_state.items()},
                "incidents":     incidents_out,
                "latencyMs":     round(latency_ms, 2),
                "framesBlocked": dropped_frames,
            })

            await asyncio.sleep(sleep_s)

        await send_fn({"type": "done", "scenario": scenario})
