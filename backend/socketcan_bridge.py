#!/usr/bin/env python3

import socket
import struct
import time

INPUT_IFACE = "vcan0"
OUTPUT_IFACE = "vcan1"

CAN_FRAME_FMT = "=IB3x8s"
CAN_FRAME_SIZE = struct.calcsize(CAN_FRAME_FMT)

CAN_EFF_FLAG = 0x80000000
CAN_EFF_MASK = 0x1FFFFFFF
CAN_SFF_MASK = 0x000007FF


def create_can_socket(interface):
    sock = socket.socket(
        socket.AF_CAN,
        socket.SOCK_RAW,
        socket.CAN_RAW
    )

    sock.bind((interface,))
    return sock


def decode_frame(raw):
    can_id_raw, dlc, data = struct.unpack(CAN_FRAME_FMT, raw)

    if can_id_raw & CAN_EFF_FLAG:
        can_id = can_id_raw & CAN_EFF_MASK
    else:
        can_id = can_id_raw & CAN_SFF_MASK

    return can_id, dlc, data[:dlc]


def main():

    print("=" * 60)
    print(" AutoShield Edge AI")
    print(" Raspberry Pi SocketCAN Inline Gateway")
    print("=" * 60)

    print(f"Input : {INPUT_IFACE}")
    print(f"Output: {OUTPUT_IFACE}")
    print()

    rx = create_can_socket(INPUT_IFACE)
    tx = create_can_socket(OUTPUT_IFACE)

    frame_count = 0
    start = time.monotonic()

    print("Gateway ACTIVE")
    print("Press Ctrl+C to stop.\n")

    try:

        while True:

            raw = rx.recv(CAN_FRAME_SIZE)

            can_id, dlc, payload = decode_frame(raw)

            # Transparent forwarding for Stage 1.
            tx.send(raw)

            frame_count += 1

            payload_hex = payload.hex(" ").upper()

            print(
                f"FORWARD  "
                f"ID=0x{can_id:03X}  "
                f"DLC={dlc}  "
                f"DATA={payload_hex}"
            )

    except KeyboardInterrupt:

        elapsed = time.monotonic() - start

        print("\nGateway stopped.")
        print(f"Frames forwarded: {frame_count}")

        if elapsed > 0:
            print(
                f"Average rate: "
                f"{frame_count / elapsed:.2f} frames/sec"
            )

    finally:
        rx.close()
        tx.close()


if __name__ == "__main__":
    main()
