"""
False-positive isolation analysis for IsolationForest on real HCRL data.
Run from src/: python fp_analysis.py
"""
import sys, os
import numpy as np
import pandas as pd

sys.path.insert(0, ".")
from feature_extraction import load_can_csv, build_baseline_profile, extract_window_features, FEATURE_COLUMNS
from detector import CANAnomalyDetector

DATA_DIR  = "../data"
MODEL_DIR = "../models"

# ── Load baseline + model ──────────────────────────────────────────────────────
print("Loading normal baseline...")
df_normal = load_can_csv(f"{DATA_DIR}/can_normal.csv")
profile, known_ids = build_baseline_profile(df_normal)
feat_normal = extract_window_features(df_normal, 200, profile, known_ids)

iso = CANAnomalyDetector.load(f"{MODEL_DIR}/can_isoforest_baseline")
print(f"Known IDs ({len(known_ids)}): {sorted(known_ids)}\n")

# True attacker IDs per scenario (from HCRL paper + our earlier inspection)
TRUE_ATTACKERS = {
    "dos":   {"0000"},                  # highest-priority flood ID
    "fuzzy": known_ids,                 # attacker uses NEW ids → anything NOT in known_ids is attacker
    "spoof": {"0316", "043F"},          # RPM + gear spoofing
}

def analyse(mode: str):
    print("=" * 70)
    print(f"SCENARIO: {mode.upper()}")
    print("=" * 70)

    df = load_can_csv(f"{DATA_DIR}/can_{mode}.csv")
    feat = extract_window_features(df, 200, profile, known_ids)
    out  = iso.predict(feat)

    # Label: 1 if this (window × CAN_ID) had at least one attack frame
    y_true = out["label"].fillna(0).astype(int)
    y_pred = out["is_anomaly"].astype(int)

    tp = ((y_pred == 1) & (y_true == 1)).sum()
    fp = ((y_pred == 1) & (y_true == 0)).sum()
    fn = ((y_pred == 0) & (y_true == 1)).sum()
    tn = ((y_pred == 0) & (y_true == 0)).sum()
    total = len(out)
    print(f"Windows: {total:,}  |  TP={tp:,}  FP={fp:,}  FN={fn:,}  TN={tn:,}")
    print(f"Precision={tp/(tp+fp):.4f}  Recall={tp/(tp+fn):.4f}  F1={2*tp/(2*tp+fp+fn):.4f}\n")

    # ── FP breakdown: which CAN IDs are falsely flagged? ──────────────────────
    fp_rows = out[(y_pred == 1) & (y_true == 0)].copy()

    if mode == "fuzzy":
        # For fuzzy, attacker uses NEW ids; innocent = known ids being falsely flagged
        fp_innocent = fp_rows[fp_rows["CAN_ID"].isin(known_ids)]
        fp_attacker_id = fp_rows[~fp_rows["CAN_ID"].isin(known_ids)]
        print(f"FP breakdown (fuzzy):")
        print(f"  Innocent known ECUs falsely flagged : {len(fp_innocent):,}")
        print(f"  New/unknown IDs flagged (OK, these ARE attacker IDs): {len(fp_attacker_id):,}")
        fp_rows = fp_innocent   # only report on innocent ECU misattribution
    else:
        true_atk = TRUE_ATTACKERS[mode]
        fp_innocent = fp_rows[~fp_rows["CAN_ID"].isin(true_atk)]
        fp_correct_id = fp_rows[fp_rows["CAN_ID"].isin(true_atk)]
        print(f"FP breakdown ({mode}):")
        print(f"  True attacker IDs : {true_atk}")
        print(f"  FP on attacker ID (already TP elsewhere in same window): {len(fp_correct_id):,}")
        print(f"  FP on INNOCENT ECUs (misattribution): {len(fp_innocent):,}")
        fp_rows = fp_innocent

    if len(fp_rows) == 0:
        print("  -> No innocent ECU isolation events. Clean.\n")
        return

    # Top innocent ECUs flagged
    top_ids = fp_rows["CAN_ID"].value_counts().head(10)
    print(f"\nTop innocent CAN IDs flagged as anomalous:")
    for cid, cnt in top_ids.items():
        pct = 100 * cnt / len(fp_rows)
        in_known = "known" if cid in known_ids else "NEW"
        print(f"  {cid}  ({in_known})  count={cnt:,}  ({pct:.1f}% of innocent FPs)")

    # ── Dominant features driving the FP flags ────────────────────────────────
    print(f"\nFeature means: FP-innocent vs true-normal windows")
    normal_out = iso.predict(feat_normal)
    tn_rows = normal_out[normal_out["is_anomaly"] == 0]

    feature_cols = ["msg_count", "msg_count_ratio", "total_msgs_in_window",
                    "unique_ids_in_window", "mean_iat", "iat_zscore",
                    "mean_entropy", "entropy_zscore", "is_new_id"]

    compare = pd.DataFrame({
        "FP_innocent_mean": fp_rows[feature_cols].mean(),
        "TN_normal_mean":   tn_rows[feature_cols].mean(),
    })
    compare["ratio_FP_vs_TN"] = (compare["FP_innocent_mean"] / compare["TN_normal_mean"].replace(0, 1e-9)).round(2)
    compare = compare.round(4)
    print(compare.to_string())

    # Highlight the biggest deviations
    print(f"\nTop features driving FP flags (highest FP/normal ratio):")
    # Exclude bus-wide features to check per-ID vs bus-wide
    per_id_feats = ["msg_count", "msg_count_ratio", "mean_iat", "iat_zscore",
                    "mean_entropy", "entropy_zscore", "is_new_id"]
    bus_wide_feats = ["total_msgs_in_window", "unique_ids_in_window"]

    sorted_feats = compare.loc[per_id_feats, "ratio_FP_vs_TN"].abs().sort_values(ascending=False)
    for feat, ratio in sorted_feats.items():
        fp_val = compare.loc[feat, "FP_innocent_mean"]
        tn_val = compare.loc[feat, "TN_normal_mean"]
        print(f"  {feat:<22} FP={fp_val:.4f}  Normal={tn_val:.4f}  ratio={ratio:.2f}x")

    bus_vals = compare.loc[bus_wide_feats]
    print(f"\nBus-wide features (shared by all IDs in window — should NOT drive per-ID isolation):")
    for feat in bus_wide_feats:
        fp_val = compare.loc[feat, "FP_innocent_mean"]
        tn_val = compare.loc[feat, "TN_normal_mean"]
        ratio  = compare.loc[feat, "ratio_FP_vs_TN"]
        print(f"  {feat:<26} FP={fp_val:.1f}  Normal={tn_val:.1f}  ratio={ratio:.2f}x")
    print()


for mode in ["dos", "fuzzy", "spoof"]:
    analyse(mode)
