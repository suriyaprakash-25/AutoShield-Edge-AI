"""
AutoShield Edge AI — Train Ensemble (Phase 3)
===============================================
Trains the full ensemble (IsoForest + LSTM-AE), then runs a 3-way comparison:

  Phase 1  IsolationForest   (retrained for fair comparison)
  Phase 2  LSTM Autoencoder  (retrained for fair comparison)
  Phase 3  Ensemble          (iso_weight=0.35, lstm_weight=0.65)

Prints a summary table and saves the ensemble to models/.

Run from inside src/:
  python train_ensemble.py
  python train_ensemble.py --data-dir /path/to/hcrl  # real dataset
  python train_ensemble.py --epochs 80 --iso-weight 0.4 --lstm-weight 0.6
"""

import argparse
import os
import sys
import time

sys.path.insert(0, ".")

import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score

from feature_extraction import FEATURE_COLUMNS, build_baseline_profile, extract_window_features, load_can_csv
from detector import CANAnomalyDetector
from lstm_detector import LSTMAnomalyDetector
from ensemble_detector import EnsembleDetector


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir",   default="../data",   help="Directory containing can_*.csv files")
    p.add_argument("--model-dir",  default="../models", help="Directory to save trained models")
    p.add_argument("--epochs",     type=int,   default=60,   help="LSTM training epochs")
    p.add_argument("--iso-weight", type=float, default=0.35, help="IsoForest weight in ensemble")
    p.add_argument("--lstm-weight",type=float, default=0.65, help="LSTM weight in ensemble")
    p.add_argument("--threshold",  type=float, default=0.50, help="Ensemble anomaly threshold")
    return p.parse_args()


def evaluate_model(model, attack_feats: dict) -> dict:
    """Run model.predict() on each attack dataset, return metrics dict."""
    results = {}
    for mode, feat in attack_feats.items():
        out = model.predict(feat)
        y_true = out["label"].fillna(0).astype(int)
        y_pred = out["is_anomaly"].astype(int)
        results[mode] = {
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall":    recall_score   (y_true, y_pred, zero_division=0),
            "f1":        f1_score       (y_true, y_pred, zero_division=0),
        }
    return results


def print_comparison(iso_r, lstm_r, ens_r):
    attack_modes = ["dos", "fuzzy", "spoof"]
    metrics = ["precision", "recall", "f1"]

    header = f"{'Attack':<8}  {'Metric':<12}  {'Phase1 IsoForest':>17}  {'Phase2 LSTM-AE':>15}  {'Phase3 Ensemble':>16}"
    print()
    print("=" * len(header))
    print("3-WAY MODEL COMPARISON")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    for mode in attack_modes:
        for m in metrics:
            v1 = iso_r[mode][m]
            v2 = lstm_r[mode][m]
            v3 = ens_r[mode][m]
            best = max(v1, v2, v3)
            def fmt(v):
                return f"{'>>>' if v == best else '   '} {v:.4f}"
            print(f"{mode.upper():<8}  {m:<12}  {fmt(v1):>17}  {fmt(v2):>15}  {fmt(v3):>16}")
        print()

    # Average recall (primary metric — missing an attack is worse than a false positive)
    avg = lambda r: sum(r[m]["recall"] for m in attack_modes) / 3
    print(f"  Avg recall  →  IsoForest: {avg(iso_r):.4f}   LSTM-AE: {avg(lstm_r):.4f}   Ensemble: {avg(ens_r):.4f}")
    print("=" * len(header))


def main():
    args = parse_args()
    os.makedirs(args.model_dir, exist_ok=True)
    t0 = time.time()

    # ── Step 1: Load data ──────────────────────────────────────────────────────
    print("=" * 70)
    print("STEP 1: Load data")
    print("=" * 70)
    df_normal = load_can_csv(f"{args.data_dir}/can_normal.csv")
    profile, known_ids = build_baseline_profile(df_normal)
    feat_normal = extract_window_features(df_normal, 200, profile, known_ids)
    print(f"Normal: {len(df_normal)} frames → {len(feat_normal)} feature rows, {len(known_ids)} known ECU IDs")

    attack_feats = {}
    for mode in ["dos", "fuzzy", "spoof"]:
        path = f"{args.data_dir}/can_{mode}.csv"
        if not os.path.exists(path):
            print(f"  WARNING: {path} not found, skipping {mode}")
            continue
        df = load_can_csv(path)
        feat = extract_window_features(df, 200, profile, known_ids)
        attack_feats[mode] = feat
        print(f"{mode.upper()}: {len(df)} frames → {len(feat)} feature rows, {feat['label'].sum()} attack windows")

    if not attack_feats:
        print("ERROR: No attack datasets found. Run generate_dataset.py first.")
        sys.exit(1)

    # ── Step 2: Train IsoForest (Phase 1) ─────────────────────────────────────
    print()
    print("=" * 70)
    print("STEP 2: Train IsolationForest (Phase 1)")
    print("=" * 70)
    iso = CANAnomalyDetector(contamination=0.05)
    iso.fit(feat_normal)
    print("IsolationForest trained.")
    iso_results = evaluate_model(iso, attack_feats)

    # ── Step 3: Train LSTM-AE (Phase 2) ───────────────────────────────────────
    print()
    print("=" * 70)
    print("STEP 3: Train LSTM Autoencoder (Phase 2)")
    print("=" * 70)
    lstm = LSTMAnomalyDetector()
    lstm.fit(feat_normal, epochs=args.epochs, verbose=True)
    lstm_results = evaluate_model(lstm, attack_feats)

    # ── Step 4: Train Ensemble (Phase 3) ──────────────────────────────────────
    print()
    print("=" * 70)
    print("STEP 4: Build Ensemble (Phase 3) — reusing sub-models already trained")
    print("=" * 70)
    ensemble = EnsembleDetector(
        iso_weight=args.iso_weight,
        lstm_weight=args.lstm_weight,
        threshold=args.threshold,
    )
    # Reuse already-trained sub-models (no extra training cost)
    ensemble.iso = iso
    ensemble.lstm = lstm
    ensemble.train_means = feat_normal[FEATURE_COLUMNS].mean()
    ensemble.train_stds = feat_normal[FEATURE_COLUMNS].std().replace(0, 1e-6)
    ensemble.is_fitted = True
    ens_results = evaluate_model(ensemble, attack_feats)
    print(f"Ensemble weights: IsoForest={args.iso_weight}, LSTM={args.lstm_weight}, threshold={args.threshold}")

    # ── Step 5: Print comparison ───────────────────────────────────────────────
    print_comparison(iso_results, lstm_results, ens_results)

    # ── Step 6: Save all models ────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("STEP 5: Save models")
    print("=" * 70)
    iso.save(f"{args.model_dir}/can_isoforest_baseline")
    print(f"  Phase 1 saved → {args.model_dir}/can_isoforest_baseline_*")

    lstm.save(f"{args.model_dir}/can_lstm_baseline")
    print(f"  Phase 2 saved → {args.model_dir}/can_lstm_baseline_*")

    ensemble.save(f"{args.model_dir}/can_ensemble")
    print(f"  Phase 3 saved → {args.model_dir}/can_ensemble_*")

    print(f"\nTotal training time: {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
