"""
AutoShield Edge AI — HCRL Car Hacking Dataset Downloader (Phase 4)
===================================================================
Downloads the real HCRL Car Hacking Dataset (Korea University) and
converts it to the standard schema used by this project.

HCRL dataset info:
  Source:  https://ocslab.hksecurity.net/Dataset/CAN-intrusion-dataset
  Paper:   Kang & Kang, "Intrusion Detection System Using Deep Neural Network
           for In-Vehicle Network Security", PLOS ONE 2016
  License: Research/educational use

Files in the dataset:
  DoS_dataset.csv   — Denial-of-Service attack (single CAN ID flood)
  Fuzzy_dataset.csv — Fuzzy/random ID + payload injection
  RPM_dataset.csv   — RPM spoofing (known ECU, spoofed payload)
  gear_dataset.csv  — Gear spoofing (known ECU, spoofed payload)

Original schema: Timestamp,CAN_ID,DLC,DATA0..DATA7,Flag
  Flag = 'R' (normal/regular) or 'T' (attack/transmitted)

This script:
  1. Downloads the 4 attack files from HCRL
  2. Normalises CAN_ID to uppercase 4-char hex (matching our schema)
  3. Extracts a clean normal (Flag=='R') slice as can_normal.csv
  4. Splits RPM + gear spoofing into a combined can_spoof.csv
  5. Saves everything to --out-dir (default ../data/)

Usage:
  cd src
  python download_hcrl.py                  # downloads to ../data/
  python download_hcrl.py --out-dir /tmp/hcrl
  python download_hcrl.py --local /path/to/downloaded/files  # preprocess only
"""

import argparse
import os
import sys
import urllib.request
import urllib.error

import pandas as pd


# ── Dataset configuration ─────────────────────────────────────────────────────

HCRL_BASE = "https://ocslab.hksecurity.net/Dataset/CAN-intrusion-dataset"

HCRL_FILES = {
    "dos":   f"{HCRL_BASE}/DoS_dataset.csv",
    "fuzzy": f"{HCRL_BASE}/Fuzzy_dataset.csv",
    "rpm":   f"{HCRL_BASE}/RPM_dataset.csv",
    "gear":  f"{HCRL_BASE}/gear_dataset.csv",
}

# Kaggle mirror (if official site is down) — user must download manually
KAGGLE_NOTE = """
  If the HCRL download fails (site occasionally returns 403), get the files from:
  https://www.kaggle.com/datasets/krishnagfk/hcrl-car-hacking-dataset
  Place the CSVs in --local <folder> and re-run with --local.
"""

NORMAL_ROWS_TARGET = 200_000   # extract this many normal rows for training baseline


# ── Download helper ───────────────────────────────────────────────────────────

def download_file(url: str, dest: str) -> bool:
    """Download url → dest. Returns True on success."""
    print(f"  Downloading {url}")
    try:
        headers = {"User-Agent": "Mozilla/5.0 (AutoShield-HCRL-Downloader/1.0)"}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as f:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            chunk = 1 << 20  # 1 MB
            while True:
                block = resp.read(chunk)
                if not block:
                    break
                f.write(block)
                downloaded += len(block)
                if total:
                    pct = downloaded / total * 100
                    print(f"\r    {downloaded // 1024:,} KB / {total // 1024:,} KB  ({pct:.1f}%)", end="", flush=True)
        print()
        return True
    except urllib.error.URLError as e:
        print(f"\n  FAILED: {e}")
        return False


# ── Schema normalisation ──────────────────────────────────────────────────────

def normalise_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalise a raw HCRL CSV to our standard schema:
      - CAN_ID: uppercase, zero-padded to 4 chars
      - DATA0..7: uppercase hex strings (or empty string for missing DLC bytes)
      - Flag: 'T' for attack, 'R' for normal (HCRL already uses this)
      - Timestamp: float seconds (HCRL uses fractional seconds already)
    """
    # Column name variants in different HCRL releases
    rename = {}
    for col in df.columns:
        if col.lower() in ("timestamp", "time"):
            rename[col] = "Timestamp"
        elif col.upper() == "CAN_ID" or col.lower() == "can_id":
            rename[col] = "CAN_ID"
        elif col.upper() == "DLC":
            rename[col] = "DLC"
        elif col.upper() == "FLAG":
            rename[col] = "Flag"
        else:
            for i in range(8):
                if col.upper() == f"DATA{i}":
                    rename[col] = f"DATA{i}"
    df = df.rename(columns=rename)

    # Ensure required columns
    required = ["Timestamp", "CAN_ID", "Flag"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}. Got: {list(df.columns)}")

    # Normalise CAN_ID to uppercase 4-char hex (e.g. "316" → "0316", "0x0260" → "0260")
    df["CAN_ID"] = df["CAN_ID"].astype(str).str.upper().str.strip()
    df["CAN_ID"] = df["CAN_ID"].str.replace("^0X", "", regex=True)
    df["CAN_ID"] = df["CAN_ID"].str.zfill(4)

    # Normalise data bytes to uppercase hex
    for i in range(8):
        col = f"DATA{i}"
        if col in df.columns:
            df[col] = df[col].fillna("00").astype(str).str.upper().str.strip().str.zfill(2)
        else:
            df[col] = "00"

    df["Timestamp"] = pd.to_numeric(df["Timestamp"], errors="coerce")
    df["Flag"] = df["Flag"].astype(str).str.strip().str.upper()
    # Some releases use 'R'=normal, 'T'=attack — ensure 'T' means attack
    # Map any variant ('1', 'ATTACK', 'A') to 'T'; everything else to 'R'
    df["Flag"] = df["Flag"].map(lambda v: "T" if v in ("T", "1", "ATTACK", "A") else "R")

    if "DLC" not in df.columns:
        df["DLC"] = 8

    return df[["Timestamp", "CAN_ID", "DLC"] + [f"DATA{i}" for i in range(8)] + ["Flag"]]


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--out-dir", default="../data", help="Output directory")
    p.add_argument("--local",   default=None, help="Path to already-downloaded HCRL files (skip download)")
    p.add_argument("--normal-rows", type=int, default=NORMAL_ROWS_TARGET,
                   help="Max normal rows to extract for baseline training")
    return p.parse_args()


def main():
    args = parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    cache_dir = args.local or os.path.join(args.out_dir, "_hcrl_raw")
    os.makedirs(cache_dir, exist_ok=True)

    # ── Download ──────────────────────────────────────────────────────────────
    if args.local is None:
        print("Downloading HCRL Car Hacking Dataset…")
        any_failed = False
        for key, url in HCRL_FILES.items():
            dest = os.path.join(cache_dir, f"{key}_dataset.csv")
            if os.path.exists(dest):
                print(f"  {dest} already exists, skipping download")
                continue
            if not download_file(url, dest):
                any_failed = True
        if any_failed:
            print()
            print("Some downloads failed. Manual download instructions:")
            print(KAGGLE_NOTE)
            print("  Place downloaded CSVs as:")
            for key in HCRL_FILES:
                print(f"    {cache_dir}/{key}_dataset.csv")
            sys.exit(1)
    else:
        print(f"Using local files from: {args.local}")

    # ── Load + normalise ──────────────────────────────────────────────────────
    print("\nNormalising datasets…")
    raw = {}
    for key in HCRL_FILES:
        path = os.path.join(cache_dir, f"{key}_dataset.csv")
        if not os.path.exists(path):
            print(f"  WARNING: {path} not found, skipping")
            continue
        print(f"  Reading {path}…")
        df = pd.read_csv(path, dtype=str)
        raw[key] = normalise_df(df)
        n_attack = (raw[key]["Flag"] == "T").sum()
        print(f"    {len(raw[key]):,} rows, {n_attack:,} attack frames ({n_attack / len(raw[key]) * 100:.1f}%)")

    # ── Extract normal baseline from DoS dataset (largest normal slice) ───────
    normal_src = raw.get("dos") or next(iter(raw.values()))
    normal_df = normal_src[normal_src["Flag"] == "R"].head(args.normal_rows)
    normal_path = os.path.join(args.out_dir, "can_normal.csv")
    normal_df.to_csv(normal_path, index=False)
    print(f"\n  Normal baseline: {len(normal_df):,} rows → {normal_path}")

    # ── Save individual attack datasets ───────────────────────────────────────
    for key in ("dos", "fuzzy"):
        if key not in raw:
            continue
        out_path = os.path.join(args.out_dir, f"can_{key}.csv")
        raw[key].to_csv(out_path, index=False)
        print(f"  {key.upper()}: {len(raw[key]):,} rows → {out_path}")

    # Merge RPM + gear into combined spoofing dataset
    spoof_parts = [raw[k] for k in ("rpm", "gear") if k in raw]
    if spoof_parts:
        spoof_df = pd.concat(spoof_parts, ignore_index=True).sort_values("Timestamp")
        spoof_path = os.path.join(args.out_dir, "can_spoof.csv")
        spoof_df.to_csv(spoof_path, index=False)
        print(f"  SPOOF (RPM+gear): {len(spoof_df):,} rows → {spoof_path}")
    else:
        print("  WARNING: No RPM/gear files found — can_spoof.csv not created")

    print(f"\nDone. Re-train models with:")
    print(f"  cd src && python train_ensemble.py --data-dir {args.out_dir}")


if __name__ == "__main__":
    main()
