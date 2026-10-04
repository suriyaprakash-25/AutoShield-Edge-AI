#!/usr/bin/env python3

import math
import socket
import struct
import time


IFACE = "vcan0"
FMT = "=IB3x8s"


def send_window(sock, label, can_id, payload, count=8, spacing=0.010):

    now = time.monotonic()

    start = (
        (math.floor(now / 0.1) + 1) * 0.1
        + 0.005
    )

    delay = start - time.monotonic()

    if delay > 0:
        time.sleep(delay)

    frame = struct.pack(
        FMT,
        can_id,
        8,
        bytes(payload),
    )

    timestamps = []

    for i in range(count):

        due = start + i * spacing

        delay = due - time.monotonic()

        if delay > 0:
            time.sleep(delay)

        timestamps.append(time.monotonic())
        sock.send(frame)

    print(
        f"{label:<13} "
        f"ID=0x{can_id:03X} "
        f"frames={count} "
        f"payload={bytes(payload).hex().upper()}"
    )

    if len(timestamps) > 1:

        iats = [
            (
                timestamps[i]
                - timestamps[i - 1]
            ) * 1000
            for i in range(1, len(timestamps))
        ]

        print(
            f"  mean sender spacing: "
            f"{sum(iats) / len(iats):.3f} ms"
        )

    # Separate the next scenario into another window.
    time.sleep(0.20)


def main():

    sock = socket.socket(
        socket.AF_CAN,
        socket.SOCK_RAW,
        socket.CAN_RAW,
    )

    sock.bind((IFACE,))

    print("=" * 66)
    print("AutoShield Hybrid-v4 Controlled Live ML Test")
    print("=" * 66)
    print()

    # RPM control
    send_window(
        sock,
        "RPM NORMAL",
        0x316,
        [32, 41, 80, 106, 41, 32, 3, 171],
    )

    # RPM anomaly
    send_window(
        sock,
        "RPM ATTACK",
        0x316,
        [60, 24, 35, 213, 24, 37, 0, 231],
    )

    # Gear control
    send_window(
        sock,
        "GEAR NORMAL",
        0x43F,
        [3, 65, 96, 255, 119, 152, 8, 0],
    )

    # Gear anomaly
    send_window(
        sock,
        "GEAR ATTACK",
        0x43F,
        [11, 67, 98, 252, 128, 81, 4, 3],
    )

    sock.close()

    print()
    print("Expected gateway result:")
    print("  RPM ATTACK  -> ML_RPM")
    print("  GEAR ATTACK -> ML_GEAR")
    print("  Normal cases should not trigger ML alerts.")


if __name__ == "__main__":
    main()
