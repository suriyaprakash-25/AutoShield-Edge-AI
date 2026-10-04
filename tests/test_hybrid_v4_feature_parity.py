#!/usr/bin/env python3

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "backend"))

from live_gateway_v2 import ExactStreamingWindow


REFERENCE = (
    ROOT
    / "reference"
    / "b200_hybrid_v4"
    / "hybrid_v4_edge_runtime.py"
)


def run_parity_test():

    if not REFERENCE.exists():
        raise SystemExit(
            f"B200 reference runtime not found: {REFERENCE}"
        )

    spec = importlib.util.spec_from_file_location(
        "b200_reference",
        REFERENCE,
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    ReferenceWindow = module.StreamingWindow

    live = ExactStreamingWindow(0.1)
    ref = ReferenceWindow(0.1)

    frames = [
        (100.001, 0x316, [10,20,30,40,50,60,70,80]),
        (100.011, 0x316, [11,21,31,41,51,61,71,81]),
        (100.017, 0x130, [1,2,3,4,5,6,7,8]),
        (100.041, 0x316, [15,25,35,45,55,65,75,85]),
        (100.071, 0x43F, [100,110,120,130,140,150,160,170]),
        (100.099, 0x43F, [101,111,121,131,141,151,161,171]),

        (100.105, 0x316, [20,30,40,50,60,70,80,90]),
        (100.120, 0x316, [21,31,41,51,61,71,81,91]),

        # Deliberately test short-DLC semantics.
        (100.140, 0x130, [1,2,3,4]),
        (100.160, 0x130, [2,3,4,5,6,7,8,9]),
    ]

    live_rows = []
    ref_rows = []

    for ts, can_id, payload in frames:

        a = live.push(ts, can_id, payload)
        b = ref.push(ts, can_id, payload)

        if a is not None:
            live_rows.extend(a)

        if b is not None:
            ref_rows.extend(b)

    live_rows.extend(live.finish())
    ref_rows.extend(ref.finish())

    assert live_rows == ref_rows, (
        "Hybrid-v4 live feature extraction differs "
        "from recovered B200 runtime"
    )

    print("EXACT B200 FEATURE PARITY ✅")
    print(f"Rows compared: {len(live_rows)}")


if __name__ == "__main__":
    run_parity_test()
