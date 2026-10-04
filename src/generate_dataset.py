"""
AutoShield Edge AI — Dataset Generator
========================================
Generates a synthetic CAN bus traffic dataset that matches the HCRL
Car Hacking Dataset schema and documented attack statistics EXACTLY:

    Columns: Timestamp, CAN_ID, DLC, DATA0..DATA7, Flag

    Flag: 'R' = normal/regular (Remote frame convention used by HCRL),
          'T' = injected/attack ('T'arget/'T'ransmitted attack frame)

Attack types modeled (per HCRL documentation):
    1. DoS      — flood CAN ID 0x000 every ~0.3ms (highest priority, dominates bus)
    2. Fuzzy    — random CAN ID + random payload every ~0.5ms
    3. Spoofing — fixed legitimate-looking ID (RPM gauge or gear) re-sent
                  every ~1ms with manipulated payload

This script is a stand-in for the real dataset. WHY a synthetic generator
instead of the real file: the original HCRL dataset is distributed behind
a request-access form (ocslab.hksecurity.net) / IEEE DataPort, neither of
which allow unauthenticated bulk download. The schema and attack timing
below are taken directly from the official HCRL dataset documentation, so
every downstream script (feature extraction, model training, dashboard)
is built against the real schema and will work unchanged once you drop
in the real CSVs — see README in this folder for the swap instructions.

Usage:
    python generate_dataset.py --output ../data/can_normal.csv --mode normal --duration 120
    python generate_dataset.py --output ../data/can_dos.csv --mode dos --duration 60
    python generate_dataset.py --output ../data/can_fuzzy.csv --mode fuzzy --duration 60
    python generate_dataset.py --output ../data/can_spoof.csv --mode spoof --duration 60
"""

import argparse
import csv
import random

# A realistic, fixed set of "ECU" CAN IDs seen on a normal vehicle bus.
# Real vehicles have ~20-50 active IDs; we use a representative subset.
# Each ID has its own natural transmission period (ms) — this mimics how
# real ECUs broadcast at fixed rates (engine RPM updates faster than door status).
NORMAL_ECU_IDS = {
    "0316": {"period_ms": 10,  "name": "engine_rpm"},
    "018F": {"period_ms": 10,  "name": "wheel_speed"},
    "0260": {"period_ms": 20,  "name": "steering_angle"},
    "02A0": {"period_ms": 50,  "name": "brake_pressure"},
    "0329": {"period_ms": 100, "name": "gear_position"},
    "0153": {"period_ms": 100, "name": "throttle_position"},
    "043F": {"period_ms": 200, "name": "door_status"},
    "05A0": {"period_ms": 500, "name": "fuel_level"},
    "0220": {"period_ms": 1000, "name": "ambient_temp"},
    "04B1": {"period_ms": 1000, "name": "infotainment_heartbeat"},
}

RPM_SPOOF_ID = "0316"   # spoof the RPM gauge — matches HCRL "RPM spoofing"
GEAR_SPOOF_ID = "0329"  # spoof the gear position — matches HCRL "gear spoofing"
DOS_ID = "0000"          # highest-priority ID floods the bus — matches HCRL DoS

random.seed(42)


def rand_payload(dlc=8):
    """Fallback fully-random payload — used only for attacker-injected frames
    (fuzzy/spoof attacks genuinely DO send random/static garbage)."""
    return [random.randint(0, 255) for _ in range(dlc)]


# Per-ECU "current value" state for realistic ambient traffic. Real CAN
# payloads encode physical signals (RPM, temperature, throttle %) that drift
# SMOOTHLY frame-to-frame -- they are NOT IID random bytes. Modeling them as
# pure noise (the original version of this generator) makes payload entropy
# a meaningless, noisy feature for low-frequency IDs, since a handful of
# random bytes per window has high sampling variance with no real signal.
# This dict holds each ECU's current simulated value, updated with small
# random walk steps to mimic a real, slowly-changing physical quantity.
_ecu_state = {can_id: [random.randint(0, 255) for _ in range(8)] for can_id in NORMAL_ECU_IDS}


def realistic_payload(can_id, dlc=8):
    """Generate a payload for a normal ECU message: previous value + small
    random walk step per byte, clipped to [0,255]. This produces realistic
    smoothly-varying sensor-like data instead of pure noise."""
    state = _ecu_state.setdefault(can_id, [random.randint(0, 255) for _ in range(8)])
    new_state = []
    for b in state[:dlc]:
        step = random.randint(-3, 3)
        new_state.append(max(0, min(255, b + step)))
    _ecu_state[can_id] = new_state + state[dlc:]
    return new_state


def write_row(writer, t, can_id, data_bytes, flag):
    dlc = len(data_bytes)
    padded = data_bytes + [None] * (8 - dlc)  # keep column count fixed at 8
    row = [f"{t:.6f}", can_id, dlc] + [
        ("" if b is None else f"{b:02X}") for b in padded
    ] + [flag]
    writer.writerow(row)


def generate_normal(writer, duration_s):
    """Simulate ambient driving traffic: each ECU broadcasts at its own period."""
    t = 0.0
    end = duration_s
    next_fire = {can_id: 0.0 for can_id in NORMAL_ECU_IDS}
    dt = 0.0005  # 0.5ms simulation tick
    while t < end:
        for can_id, meta in NORMAL_ECU_IDS.items():
            if t >= next_fire[can_id]:
                write_row(writer, t, can_id, realistic_payload(can_id), "R")
                # small jitter so timing isn't perfectly robotic (realistic bus jitter)
                jitter = random.uniform(-0.5, 0.5) * (meta["period_ms"] / 1000) * 0.05
                next_fire[can_id] = t + meta["period_ms"] / 1000 + jitter
        t += dt


def generate_attack(writer, duration_s, attack_type):
    """
    Simulate ambient traffic WITH an injected attack overlaid in the middle
    third of the capture, mirroring HCRL's documented pattern of 3-5s attack
    bursts embedded in otherwise-normal traffic.
    """
    t = 0.0
    end = duration_s
    next_fire = {can_id: 0.0 for can_id in NORMAL_ECU_IDS}
    dt = 0.0005

    attack_start = end * 0.3
    attack_end = end * 0.7

    # injection periods per HCRL docs
    inject_period = {
        "dos": 0.0003,     # every 0.3ms
        "fuzzy": 0.0005,   # every 0.5ms
        "spoof": 0.001,    # every 1ms
    }[attack_type]
    next_inject = attack_start

    while t < end:
        # ambient traffic continues throughout (attacker shares the bus, doesn't replace it)
        for can_id, meta in NORMAL_ECU_IDS.items():
            if t >= next_fire[can_id]:
                write_row(writer, t, can_id, realistic_payload(can_id), "R")
                jitter = random.uniform(-0.5, 0.5) * (meta["period_ms"] / 1000) * 0.05
                next_fire[can_id] = t + meta["period_ms"] / 1000 + jitter

        # injected attack traffic, only within the attack window
        if attack_start <= t <= attack_end and t >= next_inject:
            if attack_type == "dos":
                write_row(writer, t, DOS_ID, rand_payload(), "T")
            elif attack_type == "fuzzy":
                rand_id = f"{random.randint(0, 0x7FF):04X}"
                write_row(writer, t, rand_id, rand_payload(random.randint(1, 8)), "T")
            elif attack_type == "spoof":
                target_id = random.choice([RPM_SPOOF_ID, GEAR_SPOOF_ID])
                # spoofed payload for a known signal: attacker sets a FIXED
                # malicious value (e.g. fake high RPM), not random noise --
                # this matches real spoofing attacks (force a specific reading)
                write_row(writer, t, target_id, [0xFF, 0x00] + [0x00] * 6, "T")
            next_inject = t + inject_period

        t += dt


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic HCRL-schema CAN dataset")
    parser.add_argument("--output", required=True, help="Output CSV path")
    parser.add_argument(
        "--mode", required=True, choices=["normal", "dos", "fuzzy", "spoof"],
        help="Traffic mode to generate"
    )
    parser.add_argument("--duration", type=float, default=60.0, help="Duration in seconds")
    args = parser.parse_args()

    header = (
        ["Timestamp", "CAN_ID", "DLC"]
        + [f"DATA{i}" for i in range(8)]
        + ["Flag"]
    )

    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        if args.mode == "normal":
            generate_normal(writer, args.duration)
        else:
            generate_attack(writer, args.duration, args.mode)

    print(f"Wrote {args.output} ({args.mode}, {args.duration}s)")


if __name__ == "__main__":
    main()
