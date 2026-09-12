"""
AutoShield Edge AI — HCRL Dataset Normalizer
=============================================
Converts the raw HCRL Car Hacking Dataset files (no header, lowercase hex)
into the pipeline schema: Timestamp, CAN_ID, DLC, DATA0-7, Flag

Source files expected in data/_hcrl_raw/:
  DoS_dataset.csv    — DoS attack (ID 0000 flood)
  Fuzzy_dataset.csv  — Fuzzy attack (random IDs + payloads)
  RPM_dataset.csv    — RPM spoofing (ID 0316 repeating constant payload)
  gear_dataset.csv   — Gear spoofing (ID 043f repeating constant payload)

Outputs (written to data/):
  can_normal.csv  — R-flagged rows from DoS file (cleanest normal baseline)
  can_dos.csv     — Full DoS_dataset.csv with header
  can_fuzzy.csv   — Full Fuzzy_dataset.csv with header
  can_spoof.csv   — RPM + Gear merged (both are spoofing attacks)

Run from src/:
  python normalize_hcrl.py
  python normalize_hcrl.py --raw-dir ../data/_hcrl_raw --out-dir ../data
"""

import argparse
import os
import time

import pandas as pd

COLS = ["Timestamp", "CAN_ID", "DLC"] + [f"DATA{i}" for i in range(8)] + ["Flag"]


def read_hcrl(path: str, chunksize: int = 500_000):
    """Read raw HCRL CSV (no header, lowercase hex) in chunks, yield DataFrames."""
    for chunk in pd.read_csv(
        path,
        header=None,
        names=COLS,
        on_bad_lines="skip",   # skip rare malformed lines
        dtype=str,
        chunksize=chunksize,
        low_memory=False,
    ):
        # Uppercase CAN_ID and DATA bytes
        chunk["CAN_ID"] = chunk["CAN_ID"].str.strip().str.upper().str.zfill(4)
        for i in range(8):
            chunk[f"DATA{i}"] = chunk[f"DATA{i}"].str.strip().str.upper().str.zfill(2)
        chunk["Flag"] = chunk["Flag"].str.strip()
        chunk["DLC"]  = chunk["DLC"].str.strip()
        # Drop rows where DLC < 8 caused the Flag to bleed into DATA7
        chunk = chunk[chunk["Flag"].isin(["R", "T"])]
        yield chunk


def normalise_and_save(src: str, dst: str, flag_filter: str | None = None, label: str = ""):
    """Read src, optionally filter rows by Flag, write to dst with header."""
    t0 = time.time()
    total = 0
    first = True
    for chunk in read_hcrl(src):
        if flag_filter:
            chunk = chunk[chunk["Flag"] == flag_filter]
        if chunk.empty:
            continue
        chunk[COLS].to_csv(dst, mode="w" if first else "a", header=first, index=False)
        first = False
        total += len(chunk)
    print(f"  {label}: {total:,} rows -> {os.path.basename(dst)}  [{time.time()-t0:.1f}s]")
    return total


def merge_and_save(src_list: list[str], dst: str, label: str = ""):
    """Read multiple src files, merge, write to dst with header."""
    t0 = time.time()
    total = 0
    first = True
    for src in src_list:
        for chunk in read_hcrl(src):
            chunk[COLS].to_csv(dst, mode="w" if first else "a", header=first, index=False)
            first = False
            total += len(chunk)
    print(f"  {label}: {total:,} rows -> {os.path.basename(dst)}  [{time.time()-t0:.1f}s]")
    return total


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--raw-dir", default="../data/_hcrl_raw")
    p.add_argument("--out-dir", default="../data")
    return p.parse_args()


def main():
    args = parse_args()
    raw  = args.raw_dir
    out  = args.out_dir
    os.makedirs(out, exist_ok=True)

    dos_src   = os.path.join(raw, "DoS_dataset.csv")
    fuzzy_src = os.path.join(raw, "Fuzzy_dataset.csv")
    rpm_src   = os.path.join(raw, "RPM_dataset.csv")
    gear_src  = os.path.join(raw, "gear_dataset.csv")

    for path in [dos_src, fuzzy_src, rpm_src, gear_src]:
        if not os.path.exists(path):
            print(f"ERROR: {path} not found")
            return

    print("=" * 60)
    print("HCRL Dataset Normalizer")
    print("=" * 60)

    # Normal baseline — R-flagged rows from DoS file
    print("\nExtracting normal baseline (R rows from DoS file)...")
    normalise_and_save(dos_src, os.path.join(out, "can_normal.csv"),
                       flag_filter="R", label="Normal")

    # DoS dataset — full file
    print("\nConverting DoS dataset...")
    normalise_and_save(dos_src, os.path.join(out, "can_dos.csv"),
                       label="DoS")

    # Fuzzy dataset — full file
    print("\nConverting Fuzzy dataset...")
    normalise_and_save(fuzzy_src, os.path.join(out, "can_fuzzy.csv"),
                       label="Fuzzy")

    # Spoof dataset — RPM + Gear merged
    print("\nMerging RPM + Gear -> Spoof dataset...")
    merge_and_save([rpm_src, gear_src], os.path.join(out, "can_spoof.csv"),
                   label="Spoof (RPM+Gear)")

    print("\nDone. Now run from src/:")
    print("  python train_ensemble.py --epochs 60")


if __name__ == "__main__":
    main()
