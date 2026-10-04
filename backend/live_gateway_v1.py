#!/usr/bin/env python3

from __future__ import annotations

import math
import socket
import statistics
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


def mean(values):
    return statistics.fmean(values) if values else 0.0


def std(values):
    return statistics.pstdev(values) if len(values) > 1 else 0.0


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


class WindowAccumulator:

    def __init__(self, window_seconds=0.1):
        self.window_seconds = window_seconds
        self.last_seen = {}

        now = time.monotonic()
        self.start = now
        self.end = now + window_seconds

        self.frames = {}

    def reset(self):
        self.start = self.end
        self.end = self.start + self.window_seconds
        self.frames = {}

    def add(self, ts, frame):
        can_id = frame["id"]

        previous = self.last_seen.get(can_id)
        self.last_seen[can_id] = ts

        self.frames.setdefault(can_id, []).append(
            {
                "ts": ts,
                "previous": previous,
                "dlc": frame["dlc"],
                "data": frame["data"],
            }
        )

    def bus_count(self):
        return sum(len(v) for v in self.frames.values())

    def unique_ids(self):
        return len(self.frames)

    def count_for(self, can_id):
        return len(self.frames.get(can_id, []))

    def build_sample(self, can_id):
        records = self.frames[can_id]

        count = len(records)
        total_count = self.bus_count()
        unique_ids = self.unique_ids()

        timestamps = [r["ts"] for r in records]

        if len(timestamps) > 1:
            iats = [
                timestamps[i] - timestamps[i - 1]
                for i in range(1, len(timestamps))
            ]
        elif records[0]["previous"] is not None:
            iats = [
                timestamps[0] - records[0]["previous"]
            ]
        else:
            iats = [0.0]

        dlcs = [
            r["dlc"] / 8.0
            for r in records
        ]

        features = {
            "log_count": math.log1p(count),
            "log_bus_count": math.log1p(total_count),
            "bus_ids": float(unique_ids),

            "iat_mean": mean(iats),
            "iat_std": std(iats),

            "dlc_mean": mean(dlcs),
            "dlc_std": std(dlcs),
        }

        for byte_index in range(8):

            values = []

            for r in records:
                payload = r["data"]

                if byte_index < len(payload):
                    values.append(
                        payload[byte_index] / 255.0
                    )
                else:
                    values.append(0.0)

            features[f"b{byte_index}_mean"] = mean(values)
            features[f"b{byte_index}_std"] = std(values)

        return {
            "id": can_id,
            "count": count,
            "dlc_mean": features["dlc_mean"],
            "features": features,
        }


def main():

    detector = HybridV4Detector()

    window_seconds = float(
        detector.policy["window_seconds"]
    )

    accumulator = WindowAccumulator(window_seconds)

    rx = make_socket(INPUT_IFACE)
    tx = make_socket(OUTPUT_IFACE)

    rx.settimeout(0.02)

    counters = {
        "rx": 0,
        "forward": 0,
        "drop": 0,
        "rate_limit": 0,
        "ml_alert": 0,
    }

    print("=" * 68)
    print(" AutoShield Edge AI — Hybrid-v4 Live Gateway v1")
    print("=" * 68)
    print(f"INPUT       : {INPUT_IFACE}")
    print(f"OUTPUT      : {OUTPUT_IFACE}")
    print(f"WINDOW      : {window_seconds * 1000:.0f} ms")
    print(f"ALLOWLIST   : {len(detector.allowlist)} CAN IDs")
    print("MODE        : Controlled Enforcement")
    print()
    print("ML-only anomaly = ALERT_ONLY")
    print("Rules may DROP / RATE_LIMIT")
    print()
    print("Gateway ACTIVE — Ctrl+C to stop")
    print()

    def evaluate_completed_window():

        if not accumulator.frames:
            return

        for can_id in sorted(accumulator.frames):

            sample = accumulator.build_sample(can_id)

            result = detector.evaluate(sample)

            ml_text = ""

            if result["ml_scores"]:
                for name, score in result["ml_scores"].items():
                    ml_text += (
                        f" {name.upper()}="
                        f"{score['probability']:.6f}"
                        f"/{score['threshold']:.6f}"
                    )

            if result["reasons"]:
                print(
                    f"[WINDOW] "
                    f"ID=0x{can_id:03X} "
                    f"count={sample['count']} "
                    f"ACTION={result['action']} "
                    f"REASONS={','.join(result['reasons'])}"
                    f"{ml_text}"
                )

                if any(
                    x.startswith("ML_")
                    for x in result["reasons"]
                ):
                    counters["ml_alert"] += 1

    try:

        while True:

            now = time.monotonic()

            while now >= accumulator.end:
                evaluate_completed_window()
                accumulator.reset()

            try:
                raw = rx.recv(CAN_FRAME_SIZE)
            except socket.timeout:
                continue

            now = time.monotonic()

            while now >= accumulator.end:
                evaluate_completed_window()
                accumulator.reset()

            frame = decode(raw)

            counters["rx"] += 1

            can_id = frame["id"]

            # Current Hybrid-v4 pilot was trained for
            # standard Classic CAN data frames.
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

            # Observe the incoming bus BEFORE enforcement.
            accumulator.add(now, frame)

            count = accumulator.count_for(can_id)
            dlc_norm = frame["dlc"] / 8.0

            # -----------------------------------------
            # Deterministic fast path
            # -----------------------------------------

            if can_id not in detector.allowlist:

                counters["drop"] += 1

                print(
                    f"[DROP] "
                    f"ID=0x{can_id:03X} "
                    f"reason=UNKNOWN_ID"
                )

                continue

            lo, hi = detector.dlc_range[can_id]

            if not (lo <= dlc_norm <= hi):

                counters["drop"] += 1

                print(
                    f"[DROP] "
                    f"ID=0x{can_id:03X} "
                    f"DLC={frame['dlc']} "
                    f"reason=DLC_POLICY_VIOLATION"
                )

                continue

            rate_limit = detector.rate_limit[can_id]

            if count > rate_limit:

                counters["rate_limit"] += 1

                print(
                    f"[RATE_LIMIT] "
                    f"ID=0x{can_id:03X} "
                    f"count={count} "
                    f"limit={rate_limit}/100ms"
                )

                continue

            # -----------------------------------------
            # ALLOW path
            # -----------------------------------------

            tx.send(raw)

            counters["forward"] += 1

    except KeyboardInterrupt:

        evaluate_completed_window()

        print()
        print("=" * 68)
        print(" AutoShield gateway stopped")
        print("=" * 68)

        for name, value in counters.items():
            print(f"{name:12s}: {value}")

    finally:
        rx.close()
        tx.close()


if __name__ == "__main__":
    main()
