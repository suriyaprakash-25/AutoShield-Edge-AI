"""
End-to-end response engine simulation for Spoof scenario with global baseline.
Answers: does 04B1 actually get isolated? What gates does it pass or fail?

Run from src/:  python response_engine_sim.py
"""
import sys, os, time
import numpy as np
import pandas as pd
from collections import defaultdict

sys.path.insert(0, ".")
from feature_extraction import load_can_csv, build_baseline_profile, extract_window_features
from detector import CANAnomalyDetector
from response_engine import ResponseEngine

DATA_DIR  = "../data"
MODEL_DIR = "../models"

# ── Load baseline + model ──────────────────────────────────────────────────────
print("Loading global baseline...")
t0 = time.time()
df_normal = load_can_csv(f"{DATA_DIR}/can_normal.csv")
profile, known_ids = build_baseline_profile(df_normal)
iso = CANAnomalyDetector.load(f"{MODEL_DIR}/can_isoforest_baseline")
print(f"  {len(known_ids)} known IDs  [{time.time()-t0:.1f}s]")

# ── Load Spoof dataset ─────────────────────────────────────────────────────────
print("Loading Spoof CSV (8.9M rows — takes ~2 min)...")
t0 = time.time()
df_spoof = load_can_csv(f"{DATA_DIR}/can_spoof.csv")
print(f"  {len(df_spoof):,} rows  [{time.time()-t0:.1f}s]")

# ── Feature extraction ─────────────────────────────────────────────────────────
print("Extracting features...")
t0 = time.time()
feat = extract_window_features(df_spoof, 200, profile, known_ids)
out  = iso.predict(feat)
print(f"  {len(feat):,} feature rows  [{time.time()-t0:.1f}s]")

# ── Run response engine in time order ─────────────────────────────────────────
print("\nRunning response engine (time-ordered simulation)...")
engine = ResponseEngine(
    debounce_threshold=2,
    isolation_cooldown_windows=50,
    min_isolation_confidence=0.6,
)

TARGET_IDS = {"04B1", "05A0", "0690"}   # the main FP candidates

# Track per-ID trajectory for the target IDs
trajectory = {cid: [] for cid in TARGET_IDS}  # list of (window_start, action, conf, is_severe, bus_cong)
isolation_events = defaultdict(list)           # can_id -> list of window_starts when isolated

# Process windows in strict time order
windows_sorted = sorted(out["window_start"].unique())
total_windows = len(windows_sorted)

for i, w_start in enumerate(windows_sorted):
    window_rows = out[out["window_start"] == w_start]

    for _, row in window_rows.iterrows():
        explanation = iso.explain(row)
        attack_type = iso.classify_attack_type(row)
        action, incident = engine.process_window_result(row, explanation, attack_type)

        can_id = row["CAN_ID"]
        if can_id in TARGET_IDS:
            trajectory[can_id].append({
                "w_start":       w_start,
                "is_anomaly":    int(row["is_anomaly"]),
                "confidence":    round(float(row["confidence"]), 4),
                "is_severe":     explanation.get("is_severe", None),
                "bus_cong":      explanation.get("bus_under_congestion", None),
                "entropy_z":     round(float(row.get("entropy_zscore", 0)), 3),
                "iat_z":         round(float(row.get("iat_zscore", 0)), 3),
                "consec_flags":  engine._consecutive_flags.get(can_id, 0),
                "action":        action,
                "in_isolation":  can_id in engine.isolated_ids,
            })

        if action in ("isolated", "isolated_aggregated") and incident:
            isolation_events[can_id].append(w_start)

    if i % 5000 == 0:
        print(f"  {i}/{total_windows} windows processed...", end="\r")

print(f"\nDone. {total_windows} windows processed.")

# ── Summary: all isolated IDs ──────────────────────────────────────────────────
print("\n" + "="*70)
print("ISOLATED IDs (across full Spoof scenario):")
print("="*70)
all_isolated = sorted(isolation_events.items(), key=lambda x: -len(x[1]))
if not all_isolated:
    print("  None.")
for cid, events in all_isolated:
    label = "TRUE ATTACKER" if cid in {"0316", "043F"} else "INNOCENT FP"
    print(f"  {cid}  [{label}]  isolated {len(events)} times  "
          f"first at w={events[0]:.3f}s  last at w={events[-1]:.3f}s")

# ── Deep dive: 04B1, 05A0, 0690 ───────────────────────────────────────────────
for target in TARGET_IDS:
    traj = trajectory[target]
    if not traj:
        print(f"\n{target}: no windows seen.")
        continue

    anomalous = [t for t in traj if t["is_anomaly"] == 1]
    actually_isolated = isolation_events[target]

    print(f"\n{'='*70}")
    print(f"{target} TRAJECTORY  ({len(traj)} total windows, {len(anomalous)} flagged anomalous)")
    print(f"{'='*70}")
    print(f"  Isolation events: {len(actually_isolated)}")

    if anomalous:
        confs    = [t["confidence"]  for t in anomalous]
        severes  = [t["is_severe"]   for t in anomalous]
        buscongs = [t["bus_cong"]    for t in anomalous]
        ent_zs   = [t["entropy_z"]   for t in anomalous]

        print(f"  Confidence  — min={min(confs):.3f}  max={max(confs):.3f}  "
              f"mean={sum(confs)/len(confs):.3f}  "
              f"pct>=0.6: {100*sum(c>=0.6 for c in confs)/len(confs):.1f}%")
        print(f"  is_severe=True  : {sum(severes):,} / {len(severes)} windows  "
              f"({100*sum(severes)/len(severes):.1f}%)")
        print(f"  bus_under_congestion=True: {sum(buscongs):,} / {len(buscongs)} windows  "
              f"({100*sum(buscongs)/len(buscongs):.1f}%)")
        print(f"  entropy_zscore  — mean={sum(ent_zs)/len(ent_zs):.2f}  "
              f"min={min(ent_zs):.2f}  max={max(ent_zs):.2f}")

        # Gate breakdown: of the anomalous windows, which gate filters them?
        passed_conf   = [t for t in anomalous if t["confidence"] >= 0.6 and t["is_severe"]]
        blocked_gate  = [t for t in anomalous if t["confidence"] < 0.6 or not t["is_severe"]]
        blocked_cong  = [t for t in anomalous if t["bus_cong"]]
        reached_debnc = [t for t in anomalous if t["action"] in ("flagged_monitoring", "isolated", "dropped_isolated")]

        print(f"\n  Gate analysis (of {len(anomalous)} anomalous windows):")
        print(f"    Blocked by confidence/severity gate  : {len(blocked_gate):,}")
        print(f"    Blocked by bus_congestion suppression: {len(blocked_cong):,}")
        print(f"    Passed all gates (reached debounce)  : {len(reached_debnc):,}")
        print(f"    → Actually isolated                  : {len(actually_isolated):,}")

        # Show consecutive run lengths for windows that passed all gates
        if reached_debnc:
            # Find max consecutive run
            actions_seq = [t["action"] for t in traj]
            max_run = 0
            run = 0
            for t in traj:
                if t["action"] in ("flagged_monitoring", "isolated", "dropped_isolated"):
                    run += 1
                    max_run = max(max_run, run)
                else:
                    run = 0
            print(f"    Max consecutive windows past all gates: {max_run}")
    else:
        print(f"  No anomalous windows — never flagged by model.")
