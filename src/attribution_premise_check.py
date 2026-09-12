"""
Premise verification for two-stage attribution gate (DoS + Fuzzy).
Fully vectorised — no iterrows(), no per-window Python loops.

Attribution condition per row is just:
  is_new_id == 1  OR  msg_count_ratio > MULT × normal_baseline_ratio[CAN_ID]

Because "is ID X the source in window W" only depends on X's own features
in that window, not on what other IDs are doing in W.

Run from src/:  python attribution_premise_check.py
"""
import sys, time
import numpy as np
import pandas as pd

sys.path.insert(0, ".")
from feature_extraction import load_can_csv, build_baseline_profile, extract_window_features
from detector import CANAnomalyDetector

DATA_DIR  = "../data"
MODEL_DIR = "../models"
RATIO_MULTS = [2, 3, 4, 5]

TRUE_ATTACKERS = {
    "dos":   {"0000"},
    "fuzzy": None,   # all is_new_id==1 IDs
}

print("Loading baseline + model...")
t0 = time.time()
df_normal = load_can_csv(f"{DATA_DIR}/can_normal.csv")
profile, known_ids = build_baseline_profile(df_normal)
iso = CANAnomalyDetector.load(f"{MODEL_DIR}/can_isoforest_baseline")
print(f"  done [{time.time()-t0:.1f}s]")

# Per-ID normal msg_count_ratio — single vectorised groupby
t0 = time.time()
feat_normal = extract_window_features(df_normal, 200, profile, known_ids)
normal_ratio = feat_normal.groupby("CAN_ID")["msg_count_ratio"].mean()
print(f"  Normal features [{time.time()-t0:.1f}s]")
print(f"  Per-ID baseline ratio  min={normal_ratio.min():.4f}  "
      f"max={normal_ratio.max():.4f}  mean={normal_ratio.mean():.4f}")


def analyse(mode):
    print(f"\n{'='*70}")
    print(f"SCENARIO: {mode.upper()}")
    print(f"{'='*70}")

    t0 = time.time()
    df = load_can_csv(f"{DATA_DIR}/can_{mode}.csv")
    feat = extract_window_features(df, 200, profile, known_ids)
    out  = iso.predict(feat)
    print(f"  {len(feat):,} feature rows [{time.time()-t0:.1f}s]")

    # Attach predictions and map baseline ratio for every row in one shot
    feat = feat.copy()
    feat["is_anomaly"] = out["is_anomaly"].values
    feat["label"]      = out["label"].fillna(0).astype(int).values
    feat["base_ratio"] = feat["CAN_ID"].map(normal_ratio).fillna(0.0)

    # Classify: true attacker rows vs innocent FP rows
    true_atk_ids = TRUE_ATTACKERS[mode]
    if true_atk_ids is None:
        true_atk_ids = set(feat.loc[feat["is_new_id"]==1, "CAN_ID"].unique())
        print(f"  Fuzzy new IDs (attackers): {len(true_atk_ids):,}")

    is_attacker = feat["CAN_ID"].isin(true_atk_ids)
    tp_mask = is_attacker & (feat["is_anomaly"]==1) & (feat["label"]==1)
    fp_mask = ~is_attacker & (feat["is_anomaly"]==1) & (feat["label"]==0)

    tp = feat[tp_mask]
    fp = feat[fp_mask]
    print(f"  IsoForest: {tp_mask.sum():,} TP rows  |  {fp_mask.sum():,} FP rows")

    print(f"\n  msg_count_ratio stats:")
    print(f"    TP (attackers) : mean={tp['msg_count_ratio'].mean():.4f}  "
          f"max={tp['msg_count_ratio'].max():.4f}")
    print(f"    FP (innocents) : mean={fp['msg_count_ratio'].mean():.4f}  "
          f"max={fp['msg_count_ratio'].max():.4f}")

    # ── Vectorised attribution check for each threshold ────────────────────────
    print(f"\n  {'Mult':>4}  {'TP in src':>10}  {'TP%':>6}  "
          f"{'FP not-src':>11}  {'FP%':>6}  {'FP false-attr':>14}")
    print(f"  {'-'*58}")

    for mult in RATIO_MULTS:
        # Per-row attribution flag (fully vectorised, no loops)
        tp_attributed = (tp["is_new_id"] == 1) | \
                        ((tp["base_ratio"] > 0) &
                         (tp["msg_count_ratio"] > mult * tp["base_ratio"]))
        fp_attributed = (fp["is_new_id"] == 1) | \
                        ((fp["base_ratio"] > 0) &
                         (fp["msg_count_ratio"] > mult * fp["base_ratio"]))

        tp_in  = tp_attributed.sum()
        fp_out = (~fp_attributed).sum()   # innocent IDs NOT attributed (good)
        fp_in  = fp_attributed.sum()      # innocent IDs wrongly attributed (bad)

        pct_tp = 100 * tp_in  / max(len(tp), 1)
        pct_fp = 100 * fp_out / max(len(fp), 1)
        print(f"  {mult:>4}×  {tp_in:>10,}  {pct_tp:>5.1f}%  "
              f"{fp_out:>11,}  {pct_fp:>5.1f}%  {fp_in:>14,}")

    # ── Deep dive at mult=3 ────────────────────────────────────────────────────
    mult = 3
    print(f"\n  Deep dive at {mult}× threshold:")

    tp_attributed_3 = (tp["is_new_id"]==1) | \
                      ((tp["base_ratio"]>0) & (tp["msg_count_ratio"] > mult*tp["base_ratio"]))
    fp_attributed_3 = (fp["is_new_id"]==1) | \
                      ((fp["base_ratio"]>0) & (fp["msg_count_ratio"] > mult*fp["base_ratio"]))

    # Attacker windows where attacker is missed (not attributed)
    missed_tp = tp[~tp_attributed_3]
    if not missed_tp.empty:
        print(f"  Missed TP (attacker not attributed):")
        for cid, grp in missed_tp.groupby("CAN_ID"):
            br = normal_ratio.get(cid, 0)
            print(f"    {cid}: {len(grp):,} windows  ratio_mean={grp['msg_count_ratio'].mean():.4f} "
                  f"(need >{mult*br:.4f})  is_new_id={grp['is_new_id'].iloc[0]}")
    else:
        print(f"  Missed TP: 0 windows — attacker in source 100% of the time")

    # Innocent IDs that ARE falsely attributed
    wrong_fp = fp[fp_attributed_3]
    if not wrong_fp.empty:
        print(f"  Falsely attributed innocents ({len(wrong_fp):,} windows):")
        summary = wrong_fp.groupby("CAN_ID").agg(
            count=("msg_count_ratio","count"),
            mean_ratio=("msg_count_ratio","mean"),
            max_ratio=("msg_count_ratio","max"),
        ).sort_values("count", ascending=False).head(8)
        for cid, row in summary.iterrows():
            br = normal_ratio.get(cid, 0)
            print(f"    {cid}: {row['count']:,} windows  mean_ratio={row['mean_ratio']:.4f}  "
                  f"max={row['max_ratio']:.4f}  (3×normal={3*br:.4f})")
    else:
        print(f"  Falsely attributed innocents: 0 — gate would suppress all FPs")

    # ── Attack windows with no attributed source at all ────────────────────────
    print(f"\n  Attack windows with NO attributed source (mult=3):")
    feat["is_attributed_3"] = (feat["is_new_id"]==1) | \
                              ((feat["base_ratio"]>0) &
                               (feat["msg_count_ratio"] > 3*feat["base_ratio"]))
    # Windows that have at least one attack label row
    atk_windows = set(feat[feat["label"]==1]["window_start"].unique())
    # Windows that have at least one attacker-ID row that IS attributed
    src_windows = set(
        feat[feat["CAN_ID"].isin(true_atk_ids) & feat["is_attributed_3"]
             ]["window_start"].unique()
    )
    no_source_windows = atk_windows - src_windows
    print(f"    {len(no_source_windows):,} / {len(atk_windows):,} "
          f"({100*len(no_source_windows)/max(len(atk_windows),1):.1f}%) "
          f"attack windows have no attributed source -> gate can't isolate attacker in those")


analyse("fuzzy")

print("\nDone.")
