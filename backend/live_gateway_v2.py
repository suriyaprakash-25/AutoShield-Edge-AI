#!/usr/bin/env python3
"""
AutoShield Edge AI — Hybrid-v4 Live Gateway v2

Raw SocketCAN -> exact B200 100 ms feature extraction
              -> Hybrid-v4 specialists
              -> deterministic enforcement
              -> protected SocketCAN bus

ML-only anomalies are ALERT_ONLY.
Deterministic rules may DROP or RATE_LIMIT.
"""

from __future__ import annotations

import math
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from hybrid_v4_model import HybridV4Detector


INPUT_IFACE = "vcan0"
OUTPUT_IFACE = "vcan1"

CAN_FRAME_FMT = "=IB3x8s"
CAN_FRAME_SIZE = struct.calcsize(CAN_FRAME_FMT)

CAN_EFF_FLAG = 0x80000000
CAN_RTR_FLAG = 0x40000000
CAN_ERR_FLAG = 0x20000000

CAN_EFF_MASK = 0x1FFFFFFF
CAN_SFF_MASK = 0x000007FF


def make_socket(interface):
    s = socket.socket(
        socket.AF_CAN,
        socket.SOCK_RAW,
        socket.CAN_RAW,
    )
    s.bind((interface,))
    return s


def decode(raw):
    raw_id, dlc, data = struct.unpack(CAN_FRAME_FMT, raw)

    extended = bool(raw_id & CAN_EFF_FLAG)
    rtr = bool(raw_id & CAN_RTR_FLAG)
    error = bool(raw_id & CAN_ERR_FLAG)

    if extended:
        can_id = raw_id & CAN_EFF_MASK
    else:
        can_id = raw_id & CAN_SFF_MASK

    return {
        "id": can_id,
        "dlc": dlc,
        "data": data[:dlc],
        "extended": extended,
        "rtr": rtr,
        "error": error,
    }


class ExactStreamingWindow:
    """
    Exact feature semantics recovered from the original B200
    hybrid_v4_edge_runtime.py.
    """

    def __init__(self, window_seconds=0.1):
        self.window_seconds = float(window_seconds)
        self.current_window = None
        self.last_timestamp = None
        self.states = {}

    @staticmethod
    def _std(total, squared, count):
        # Sample standard deviation, exactly as B200 runtime.
        if count <= 1:
            return 0.0

        return math.sqrt(
            max(
                0.0,
                (squared - total * total / count)
                / (count - 1),
            )
        )

    def reset(self):
        self.current_window = None
        self.last_timestamp = None
        self.states.clear()

    def count_for(self, can_id):
        state = self.states.get(int(can_id))
        return state["n"] if state is not None else 0

    def push(self, timestamp, can_id, payload):
        timestamp = float(timestamp)
        can_id = int(can_id)
        payload = tuple(int(v) for v in payload)

        if not math.isfinite(timestamp):
            raise ValueError("Invalid CAN timestamp")

        if not 0 <= can_id <= 0x7FF:
            raise ValueError("Invalid standard CAN ID")

        if len(payload) > 8:
            raise ValueError("Invalid CAN payload")

        if any(v < 0 or v > 255 for v in payload):
            raise ValueError("Invalid CAN payload")

        if (
            self.last_timestamp is not None
            and timestamp < self.last_timestamp
        ):
            raise ValueError(
                "Timestamp moved backwards; reset at session boundary"
            )

        window = int(
            math.floor(timestamp / self.window_seconds)
        )

        emitted = None

        if (
            self.current_window is not None
            and window != self.current_window
        ):
            emitted = self.finish()

        self.current_window = window
        self.last_timestamp = timestamp

        state = self.states.setdefault(
            can_id,
            {
                "n": 0,
                "last": None,
                "iat": 0.0,
                "iat2": 0.0,
                "dlc": 0.0,
                "dlc2": 0.0,
                "sum": [0.0] * 8,
                "sum2": [0.0] * 8,
                "valid": [0] * 8,
            },
        )

        # IMPORTANT:
        # IAT is only between frames of this ID within
        # the current 100 ms window.
        if state["last"] is not None:
            delta = timestamp - state["last"]

            state["iat"] += delta
            state["iat2"] += delta * delta

        state["last"] = timestamp
        state["n"] += 1

        dlc = len(payload)

        state["dlc"] += dlc
        state["dlc2"] += dlc * dlc

        # IMPORTANT:
        # Missing bytes are NOT zero padded.
        for i, value in enumerate(payload):
            state["sum"][i] += value
            state["sum2"][i] += value * value
            state["valid"][i] += 1

        return emitted

    def finish(self):
        if self.current_window is None:
            return []

        bus_count = sum(
            state["n"]
            for state in self.states.values()
        )

        bus_ids = len(self.states)

        rows = []

        for can_id in sorted(self.states):
            state = self.states[can_id]
            n = state["n"]

            row = {
                "id": can_id,
                "window": self.current_window,
                "count": n,

                "log_count": math.log1p(n),
                "log_bus_count": math.log1p(bus_count),
                "bus_ids": bus_ids,

                # Exact B200 normalization:
                # seconds / 0.1 s
                "iat_mean":
                    state["iat"]
                    / max(1, n - 1)
                    / self.window_seconds,

                "iat_std":
                    self._std(
                        state["iat"],
                        state["iat2"],
                        n - 1,
                    )
                    / self.window_seconds,

                "dlc_mean":
                    state["dlc"]
                    / n
                    / 8.0,

                "dlc_std":
                    self._std(
                        state["dlc"],
                        state["dlc2"],
                        n,
                    )
                    / 8.0,
            }

            for i in range(8):
                valid = state["valid"][i]

                row[f"b{i}_mean"] = (
                    state["sum"][i]
                    / max(1, valid)
                    / 255.0
                )

                row[f"b{i}_std"] = (
                    self._std(
                        state["sum"][i],
                        state["sum2"][i],
                        valid,
                    )
                    / 255.0
                )

            rows.append(row)

        # B200 semantics: temporal statistics restart
        # for the next completed window.
        self.states = {}

        return rows

    def finish_if_due(self, timestamp):
        """
        Live SocketCAN addition.

        The original CSV runtime naturally finished a window
        when the next timestamp arrived. For a live bus we also
        finish an expired window during receive timeouts so the
        final window can be evaluated without requiring another
        CAN frame.
        """

        if self.current_window is None:
            return None

        current = int(
            math.floor(
                float(timestamp)
                / self.window_seconds
            )
        )

        if current == self.current_window:
            return None

        rows = self.finish()

        # No frame has yet entered the new window.
        self.current_window = None

        return rows


def main():

    detector = HybridV4Detector()

    window_seconds = float(
        detector.policy["window_seconds"]
    )

    accumulator = ExactStreamingWindow(
        window_seconds
    )

    rx = make_socket(INPUT_IFACE)
    tx = make_socket(OUTPUT_IFACE)

    rx.settimeout(0.02)

    counters = {
        "rx": 0,
        "forward": 0,
        "drop": 0,
        "rate_limit": 0,
        "ml_alert": 0,
        "windows": 0,
    }

    print("=" * 72)
    print(
        " AutoShield Edge AI — Hybrid-v4 "
        "Live Gateway v2"
    )
    print("=" * 72)

    print(f"INPUT       : {INPUT_IFACE}")
    print(f"OUTPUT      : {OUTPUT_IFACE}")
    print(
        f"WINDOW      : "
        f"{window_seconds * 1000:.0f} ms"
    )
    print(
        f"ALLOWLIST   : "
        f"{len(detector.allowlist)} CAN IDs"
    )

    print(
        "FEATURES    : Exact recovered B200 "
        "Hybrid-v4 semantics"
    )

    print("MODE        : Controlled Enforcement")
    print()
    print("ML-only anomaly = ALERT_ONLY")
    print("Rules may DROP / RATE_LIMIT")
    print()
    print("Gateway ACTIVE — Ctrl+C to stop")
    print()

    def evaluate_rows(rows):

        if not rows:
            return

        counters["windows"] += 1

        for row in rows:

            can_id = int(row["id"])

            # HybridV4Detector expects the temporal
            # feature vector inside "features".
            sample = {
                "id": can_id,
                "count": int(row["count"]),
                "dlc_mean": float(
                    row["dlc_mean"]
                ),
                "features": row,
            }

            result = detector.evaluate(sample)

            ml_text = ""

            for name, score in (
                result["ml_scores"].items()
            ):
                ml_text += (
                    f" {name.upper()}="
                    f"{score['probability']:.6f}"
                    f"/{score['threshold']:.6f}"
                )

            if result["reasons"]:

                print(
                    f"[WINDOW] "
                    f"W={row['window']} "
                    f"ID=0x{can_id:03X} "
                    f"count={row['count']} "
                    f"ACTION={result['action']} "
                    f"REASONS="
                    f"{','.join(result['reasons'])}"
                    f"{ml_text}"
                )

                if any(
                    reason.startswith("ML_")
                    for reason
                    in result["reasons"]
                ):
                    counters["ml_alert"] += 1

    try:

        while True:

            try:
                raw = rx.recv(CAN_FRAME_SIZE)

            except socket.timeout:

                completed = (
                    accumulator.finish_if_due(
                        time.monotonic()
                    )
                )

                if completed is not None:
                    evaluate_rows(completed)

                continue

            now = time.monotonic()

            frame = decode(raw)

            counters["rx"] += 1

            can_id = frame["id"]

            # Hybrid-v4 pilot supports standard
            # Classic CAN data frames only.
            if (
                frame["extended"]
                or frame["rtr"]
                or frame["error"]
            ):

                counters["drop"] += 1

                print(
                    f"[DROP] unsupported frame "
                    f"ID=0x{can_id:X}"
                )

                continue

            # -------------------------------------------------
            # Temporal observation path
            # -------------------------------------------------
            #
            # Observe BEFORE enforcement so the IDS sees the
            # incoming/raw bus, including attack traffic.
            #
            # This is the exact feature construction used by
            # the recovered B200 runtime.

            completed = accumulator.push(
                now,
                can_id,
                frame["data"],
            )

            if completed is not None:
                evaluate_rows(completed)

            current_count = (
                accumulator.count_for(can_id)
            )

            dlc_norm = frame["dlc"] / 8.0

            # -------------------------------------------------
            # Deterministic fast path
            # -------------------------------------------------

            if can_id not in detector.allowlist:

                counters["drop"] += 1

                print(
                    f"[DROP] "
                    f"ID=0x{can_id:03X} "
                    f"reason=UNKNOWN_ID"
                )

                continue

            lo, hi = detector.dlc_range[can_id]

            if not (
                lo <= dlc_norm <= hi
            ):

                counters["drop"] += 1

                print(
                    f"[DROP] "
                    f"ID=0x{can_id:03X} "
                    f"DLC={frame['dlc']} "
                    f"reason=DLC_POLICY_VIOLATION"
                )

                continue

            limit = detector.rate_limit[can_id]

            if current_count > limit:

                counters["rate_limit"] += 1

                print(
                    f"[RATE_LIMIT] "
                    f"ID=0x{can_id:03X} "
                    f"count={current_count} "
                    f"limit={limit}/100ms"
                )

                continue

            # -------------------------------------------------
            # ALLOW path
            # -------------------------------------------------

            tx.send(raw)

            counters["forward"] += 1

    except KeyboardInterrupt:

        evaluate_rows(
            accumulator.finish()
        )

        print()
        print("=" * 72)
        print(" AutoShield gateway stopped")
        print("=" * 72)

        for name, value in counters.items():
            print(
                f"{name:12s}: {value}"
            )

    finally:
        rx.close()
        tx.close()


if __name__ == "__main__":
    main()
