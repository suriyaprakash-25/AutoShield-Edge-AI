"""
AutoShield Edge AI — Comprehensive Evaluation
=============================================
Loads all trained models and evaluates them on every attack type.
Outputs a rich metrics table and optionally saves ROC curve plots.

Run from inside src/:
  python evaluate.py                      # auto-detect best available model
  python evaluate.py --model ensemble     # force ensemble
  python evaluate.py --model iso          # force IsoForest only
  python evaluate.py --model lstm         # force LSTM only
  python evaluate.py --plots             # save ROC plots to ../reports/
  python evaluate.py --data-dir /path    # use real HCRL dataset
"""

import argparse
import os
import sys
import time

sys.path.insert(0, ".")

import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, average_precision_score,
)

from feature_extraction import build_baseline_profile, extract_window_features, load_can_csv
from detector import CANAnomalyDetector
from lstm_detector import LSTMAnomalyDetector
from ensemble_detector import EnsembleDetector


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir",  default="../data",   help="CAN CSV directory")
    p.add_argument("--model-dir", default="../models", help="Trained model directory")
    p.add_argument("--model",     default="auto", choices=["auto", "ensemble", "lstm", "iso"])
    p.add_argument("--plots",     action="store_true", help="Save ROC curve PNGs to ../reports/")
    return p.parse_args()


def load_best_model(model_dir: str, force: str = "auto"):
    """Load the best available model, preferring ensemble > lstm > iso."""
    if force == "auto" or force == "ensemble":
        path = f"{model_dir}/can_ensemble_ensemble_meta.json"
        if os.path.exists(path):
            print(f"  Loading Ensemble from {model_dir}/can_ensemble_*")
            return EnsembleDetector.load(f"{model_dir}/can_ensemble"), "Ensemble"

    if force in ("auto", "lstm"):
        path = f"{model_dir}/can_lstm_baseline_lstm_meta.json"
        if os.path.exists(path):
            print(f"  Loading LSTM-AE from {model_dir}/can_lstm_baseline_*")
            return LSTMAnomalyDetector.load(f"{model_dir}/can_lstm_baseline"), "LSTM-AE"

    if force in ("auto", "iso"):
        path = f"{model_dir}/can_isoforest_baseline_meta.json"
        if os.path.exists(path):
            print(f"  Loading IsoForest from {model_dir}/can_isoforest_baseline_*")
            return CANAnomalyDetector.load(f"{model_dir}/can_isoforest_baseline"), "IsoForest"

    return None, None


def compute_metrics(y_true, y_pred, y_score=None):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    metrics = {
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall":    recall_score   (y_true, y_pred, zero_division=0),
        "f1":        f1_score       (y_true, y_pred, zero_division=0),
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        "fpr": fp / (fp + tn) if (fp + tn) > 0 else 0.0,
    }
    if y_score is not None and len(np.unique(y_true)) > 1:
        metrics["roc_auc"] = roc_auc_score(y_true, y_score)
        metrics["avg_precision"] = average_precision_score(y_true, y_score)
    else:
        metrics["roc_auc"] = float("nan")
        metrics["avg_precision"] = float("nan")
    return metrics


def print_report(model_name, all_metrics):
    attack_modes = [m for m in ["dos", "fuzzy", "spoof"] if m in all_metrics]
    print()
    print("=" * 80)
    print(f"  EVALUATION REPORT — {model_name}")
    print("=" * 80)
    print(f"  {'Attack':<8}  {'Precision':>10}  {'Recall':>8}  {'F1':>8}  {'ROC-AUC':>9}  {'FPR':>7}  TP/FP/FN")
    print("  " + "-" * 75)
    for mode in attack_modes:
        m = all_metrics[mode]
        roc = f"{m['roc_auc']:.4f}" if not np.isnan(m['roc_auc']) else "   n/a"
        print(
            f"  {mode.upper():<8}  {m['precision']:>10.4f}  {m['recall']:>8.4f}  "
            f"{m['f1']:>8.4f}  {roc:>9}  {m['fpr']:>7.4f}  "
            f"{m['tp']}/{m['fp']}/{m['fn']}"
        )

    avg_recall = sum(all_metrics[m]["recall"] for m in attack_modes) / len(attack_modes)
    avg_prec   = sum(all_metrics[m]["precision"] for m in attack_modes) / len(attack_modes)
    avg_f1     = sum(all_metrics[m]["f1"] for m in attack_modes) / len(attack_modes)
    print("  " + "-" * 75)
    print(f"  {'AVERAGE':<8}  {avg_prec:>10.4f}  {avg_recall:>8.4f}  {avg_f1:>8.4f}")
    print("=" * 80)


def save_roc_plots(all_results, report_dir):
    """Save ROC curve PNG per attack mode (only if matplotlib available)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from sklearn.metrics import roc_curve
    except ImportError:
        print("  matplotlib not installed — skipping ROC plots")
        return

    os.makedirs(report_dir, exist_ok=True)
    for mode, (y_true, y_score, model_name) in all_results.items():
        if len(np.unique(y_true)) < 2:
            continue
        fpr, tpr, _ = roc_curve(y_true, y_score)
        auc = roc_auc_score(y_true, y_score)

        fig, ax = plt.subplots(figsize=(6, 5))
        ax.plot(fpr, tpr, lw=2, label=f"AUC = {auc:.4f}")
        ax.plot([0, 1], [0, 1], "--", color="gray", lw=1)
        ax.set_xlabel("False Positive Rate")
        ax.set_ylabel("True Positive Rate")
        ax.set_title(f"ROC Curve — {mode.upper()} — {model_name}")
        ax.legend()
        ax.grid(alpha=0.3)
        path = f"{report_dir}/roc_{mode}_{model_name.lower().replace(' ', '_')}.png"
        fig.savefig(path, dpi=120, bbox_inches="tight")
        plt.close(fig)
        print(f"  ROC plot saved: {path}")


def main():
    args = parse_args()
    t0 = time.time()

    print("=" * 70)
    print("STEP 1: Load baseline profile")
    print("=" * 70)
    normal_path = f"{args.data_dir}/can_normal.csv"
    if not os.path.exists(normal_path):
        print(f"ERROR: {normal_path} not found. Run generate_dataset.py first.")
        sys.exit(1)

    df_normal = load_can_csv(normal_path)
    profile, known_ids = build_baseline_profile(df_normal)
    feat_normal = extract_window_features(df_normal, 200, profile, known_ids)
    print(f"Normal: {len(df_normal)} frames, {len(known_ids)} ECU IDs")

    print()
    print("=" * 70)
    print("STEP 2: Load attack datasets")
    print("=" * 70)
    attack_feats = {}
    for mode in ["dos", "fuzzy", "spoof"]:
        path = f"{args.data_dir}/can_{mode}.csv"
        if not os.path.exists(path):
            print(f"  SKIP: {path} not found")
            continue
        df = load_can_csv(path)
        feat = extract_window_features(df, 200, profile, known_ids)
        attack_feats[mode] = feat
        n_attack = int(feat["label"].sum()) if "label" in feat else 0
        print(f"  {mode.upper()}: {len(df)} frames → {len(feat)} windows, {n_attack} attack windows")

    if not attack_feats:
        print("ERROR: No attack datasets found.")
        sys.exit(1)

    print()
    print("=" * 70)
    print("STEP 3: Load model")
    print("=" * 70)
    model, model_name = load_best_model(args.model_dir, args.model)
    if model is None:
        print("ERROR: No trained model found. Run train_ensemble.py (or train_baseline.py) first.")
        sys.exit(1)
    print(f"  Model: {model_name}")

    print()
    print("=" * 70)
    print("STEP 4: Evaluate")
    print("=" * 70)
    all_metrics = {}
    roc_data = {}

    for mode, feat in attack_feats.items():
        out = model.predict(feat)
        y_true  = out["label"].fillna(0).astype(int).values
        y_pred  = out["is_anomaly"].astype(int).values
        y_score = out["confidence"].values if "confidence" in out else out["anomaly_score"].values
        all_metrics[mode] = compute_metrics(y_true, y_pred, y_score)
        roc_data[mode] = (y_true, y_score, model_name)

    print_report(model_name, all_metrics)

    if args.plots:
        print()
        print("Saving ROC plots…")
        save_roc_plots(roc_data, "../reports")

    print(f"\nEvaluation complete in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
