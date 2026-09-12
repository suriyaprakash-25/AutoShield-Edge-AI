"""
AutoShield Edge AI — Large-Scale HCRL-Matched Dataset Generator
================================================================
Generates HCRL-scale CAN datasets using numpy vectorisation:
  - 10-50× faster than the tick-loop generator
  - Normal: ~900s → ~360K frames  (HCRL normal slice: ~1.5M, same schema)
  - Attack: ~600s → ~250K+attack frames, with 20 repeated attack windows
    mirroring HCRL's documented pattern of 300 injections of 3-5s each

Everything downstream (feature extraction, detector, dashboard) works unchanged
because the schema (Timestamp, CAN_ID, DLC, DATA0-7, Flag) is identical.

Usage (run from src/):
  python generate_large_dataset.py
  python generate_large_dataset.py --normal-dur 1800 --attack-dur 900

This overwrites the existing data/ files, so retrain afterwards:
  python train_ensemble.py
"""

import argparse
import os
import sys
import time

import numpy as np
import pandas as pd

# Same 10 ECU IDs as the rest of the system — keeps KNOWN_IDS in sync
ECUS = {
    "0316": 10,    # engine_rpm        — 10ms period
    "018F": 10,    # wheel_speed       — 10ms
    "0260": 20,    # steering_angle    — 20ms
    "02A0": 50,    # brake_pressure    — 50ms
    "0329": 100,   # gear_position     — 100ms
    "0153": 100,   # throttle_position — 100ms
    "043F": 200,   # door_status       — 200ms
    "05A0": 500,   # fuel_level        — 500ms
    "0220": 1000,  # ambient_temp      — 1000ms
    "04B1": 1000,  # infotainment      — 1000ms
}

DOS_ID    = "0000"   # highest-priority bus flood ID
RNG = np.random.default_rng(42)


# ── Payload generation ────────────────────────────────────────────────────────

def _rand_walk_payloads(n: int, init_state: np.ndarray | None = None) -> np.ndarray:
    """
    Generate n payload rows as a smooth random walk (step ∈ [-3, 3] per byte).
    Clipped to [0, 255]. Returns uint8 array [n, 8].
    This mimics real ECU sensor signals (RPM, temp, throttle) that drift gradually
    rather than jumping randomly each frame.
    """
    steps = RNG.integers(-3, 4, size=(n, 8))
    if init_state is None:
        init_state = RNG.integers(0, 256, size=8).astype(np.int16)
    rows = np.zeros((n, 8), dtype=np.int16)
    rows[0] = np.clip(init_state + steps[0], 0, 255)
    for i in range(1, n):
        rows[i] = np.clip(rows[i-1] + steps[i], 0, 255)
    return rows.astype(np.uint8)


def _random_payloads(n: int) -> np.ndarray:
    """Fully random payloads — used for DoS/fuzzy attack frames."""
    return RNG.integers(0, 256, size=(n, 8), dtype=np.uint8)


# ── Normal traffic ────────────────────────────────────────────────────────────

def generate_normal_frames(duration_s: float) -> pd.DataFrame:
    """Generate ambient normal ECU traffic for duration_s seconds."""
    all_dfs = []

    for can_id, period_ms in ECUS.items():
        period_s = period_ms / 1000.0
        n = int(duration_s / period_s) + 1

        # Base timestamps + ±5% jitter (models real bus contention / crystal drift)
        base_ts = np.arange(n) * period_s
        jitter   = RNG.uniform(-0.05 * period_s, 0.05 * period_s, size=n)
        ts       = np.clip(base_ts + jitter, 0, duration_s)

        payloads = _rand_walk_payloads(n)

        df = pd.DataFrame({
            "Timestamp": ts,
            "CAN_ID":    can_id,
            "DLC":       8,
            **{f"DATA{i}": payloads[:, i] for i in range(8)},
            "Flag":      "R",
        })
        all_dfs.append(df)

    df_all = pd.concat(all_dfs, ignore_index=True).sort_values("Timestamp").reset_index(drop=True)
    # Format DATA columns as uppercase hex
    for i in range(8):
        df_all[f"DATA{i}"] = df_all[f"DATA{i}"].apply(lambda v: f"{int(v):02X}")
    return df_all


# ── Attack traffic overlay ────────────────────────────────────────────────────

def _attack_windows(duration_s: float, n_windows: int = 20, window_s: float = 4.0):
    """
    Generate n_windows attack start times spread across the capture,
    leaving clear normal-traffic zones between attacks.
    Mirrors HCRL's documented pattern of ~300 attacks spread over 30-40 minutes;
    we use 20 windows of 4s each for a 600s capture (same density).
    """
    total_attack = n_windows * window_s
    gap = (duration_s - total_attack) / (n_windows + 1)
    starts = [gap * (i + 1) + window_s * i for i in range(n_windows)]
    return [(s, s + window_s) for s in starts]


def generate_dos_frames(duration_s: float) -> pd.DataFrame:
    """DoS: flood bus with highest-priority ID 0x000 every ~0.3ms during attack windows."""
    normal = generate_normal_frames(duration_s)
    normal["Flag"] = "R"

    windows = _attack_windows(duration_s, n_windows=20, window_s=4.0)
    attack_dfs = []

    for w_start, w_end in windows:
        inject_period = 0.0003  # 0.3ms — matches HCRL DoS
        ts = np.arange(w_start, w_end, inject_period)
        n  = len(ts)
        payloads = _random_payloads(n)
        df = pd.DataFrame({
            "Timestamp": ts, "CAN_ID": DOS_ID, "DLC": 8,
            **{f"DATA{i}": [f"{v:02X}" for v in payloads[:, i]] for i in range(8)},
            "Flag": "T",
        })
        attack_dfs.append(df)

    attack = pd.concat(attack_dfs, ignore_index=True)
    result = pd.concat([normal, attack], ignore_index=True).sort_values("Timestamp").reset_index(drop=True)
    return result


def generate_fuzzy_frames(duration_s: float) -> pd.DataFrame:
    """Fuzzy: inject random CAN IDs + random payloads every ~0.5ms during windows."""
    normal = generate_normal_frames(duration_s)
    normal["Flag"] = "R"

    windows = _attack_windows(duration_s, n_windows=20, window_s=4.0)
    attack_dfs = []

    for w_start, w_end in windows:
        inject_period = 0.0005  # 0.5ms
        ts = np.arange(w_start, w_end, inject_period)
        n  = len(ts)

        # Random 11-bit CAN IDs (0x000-0x7FF) — mostly new, unknown IDs
        rand_ids  = RNG.integers(0x200, 0x7FF, size=n)   # upper half → unlikely to be in KNOWN_IDS
        rand_dlcs = RNG.integers(1, 9, size=n)
        payloads  = _random_payloads(n)

        df = pd.DataFrame({
            "Timestamp": ts,
            "CAN_ID":    [f"{v:04X}" for v in rand_ids],
            "DLC":       rand_dlcs,
            **{f"DATA{i}": [f"{v:02X}" for v in payloads[:, i]] for i in range(8)},
            "Flag": "T",
        })
        attack_dfs.append(df)

    attack = pd.concat(attack_dfs, ignore_index=True)
    result = pd.concat([normal, attack], ignore_index=True).sort_values("Timestamp").reset_index(drop=True)
    return result


def generate_spoof_frames(duration_s: float) -> pd.DataFrame:
    """
    Spoofing: re-send known ECU IDs (RPM=0316, Gear=0329) with fixed malicious
    payload every ~1ms. Attacker reuses a legitimate ID so it looks authentic
    but at an abnormal rate with static (manipulated) payload values.
    """
    SPOOF_IDS = ["0316", "0329"]  # RPM gauge and gear position — matches HCRL

    normal = generate_normal_frames(duration_s)
    normal["Flag"] = "R"

    windows = _attack_windows(duration_s, n_windows=20, window_s=4.0)
    attack_dfs = []

    for w_start, w_end in windows:
        inject_period = 0.001  # 1ms (10× faster than normal 10ms or 100ms period)
        ts       = np.arange(w_start, w_end, inject_period)
        n        = len(ts)
        spoof_id = RNG.choice(SPOOF_IDS, size=n)
        # Attacker forces a specific value: 0xFF 0xFF = max RPM / wrong gear
        # constant payload makes entropy drop dramatically — key detection signal
        payloads = np.full((n, 8), fill_value=0xFF, dtype=np.uint8)
        payloads[:, 2:] = 0x00  # attacker only controls first 2 bytes

        df = pd.DataFrame({
            "Timestamp": ts,
            "CAN_ID":    spoof_id,
            "DLC":       8,
            **{f"DATA{i}": [f"{v:02X}" for v in payloads[:, i]] for i in range(8)},
            "Flag": "T",
        })
        attack_dfs.append(df)

    attack = pd.concat(attack_dfs, ignore_index=True)
    result = pd.concat([normal, attack], ignore_index=True).sort_values("Timestamp").reset_index(drop=True)
    return result


# ── Writer ────────────────────────────────────────────────────────────────────

def save(df: pd.DataFrame, path: str) -> None:
    cols = ["Timestamp", "CAN_ID", "DLC"] + [f"DATA{i}" for i in range(8)] + ["Flag"]
    df["Timestamp"] = df["Timestamp"].apply(lambda v: f"{v:.6f}")
    df[cols].to_csv(path, index=False)


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir",    default="../data")
    p.add_argument("--normal-dur",  type=float, default=900,  help="Normal capture seconds")
    p.add_argument("--attack-dur",  type=float, default=600,  help="Attack capture seconds each")
    return p.parse_args()


def main():
    args = parse_args()
    os.makedirs(args.data_dir, exist_ok=True)

    tasks = [
        ("normal", args.normal_dur, generate_normal_frames,  "can_normal.csv"),
        ("dos",    args.attack_dur, generate_dos_frames,     "can_dos.csv"),
        ("fuzzy",  args.attack_dur, generate_fuzzy_frames,   "can_fuzzy.csv"),
        ("spoof",  args.attack_dur, generate_spoof_frames,   "can_spoof.csv"),
    ]

    total_rows = 0
    for mode, dur, fn, fname in tasks:
        t0 = time.time()
        print(f"Generating {mode} ({dur:.0f}s)…", end=" ", flush=True)
        df = fn(dur)
        path = os.path.join(args.data_dir, fname)
        save(df, path)
        n_attack = (df["Flag"] == "T").sum() if mode != "normal" else 0
        elapsed = time.time() - t0
        print(f"{len(df):,} frames ({n_attack:,} attack) -> {fname}  [{elapsed:.1f}s]")
        total_rows += len(df)

    print(f"\nTotal: {total_rows:,} frames across 4 datasets")
    print("Now run:  python train_ensemble.py")


if __name__ == "__main__":
    main()
