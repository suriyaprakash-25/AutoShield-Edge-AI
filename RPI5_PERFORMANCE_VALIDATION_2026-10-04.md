# AutoShield Edge AI — Raspberry Pi 5 Performance Validation

**Date:** 2026-10-04  
**Status:** Preliminary measured validation, virtual SocketCAN POC  
**Branch under test:** `pi-vcan-integration`  
**Commit under test:** `8369cdb756c9fd89799659c62302a415c0627c52`

## 1. Scope and platform

- Raspberry Pi 5, 8 GB RAM, aarch64
- Linux 6.18.50+rpt-rpi-2712
- Python 3.13.5, NumPy 2.2.4
- Runtime: `backend/live_gateway_v2.py`
- CAN transport in these measurements: Linux virtual SocketCAN
- Topology: `vcan0 -> AutoShield gateway -> vcan1`
- Hybrid-v4 observation window: 100 ms
- Deterministic rules and Hybrid-v4 specialist inference both active
- These are **not physical CAN/HIL measurements**

## 2. Model/runtime validation

Feature extraction was compared with the recovered B200 Hybrid-v4 runtime:

```text
EXACT B200 FEATURE PARITY ✅
Rows compared: 5
```

Latest Phase F/G regression validation on the Pi:

```text
Ran 10 tests in 2.223s
OK
```

Dashboard production build and lint also passed:

```text
vite build: PASS
oxlint: 0 warnings, 0 errors
```

## 3. Exact benign forwarding test

A controlled benign `0x130` stream was sent below the deterministic rate limit.

| Metric | Result |
|---|---:|
| Generated frames | 1,000 |
| Gateway RX | 1,000 |
| Gateway forwarded | 1,000 |
| Protected-side capture | 1,000 |
| Drop | 0 |
| Rate-limited | 0 |
| ML alerts | 0 |
| Virtual delivery ratio | **100.0%** |

## 4. Sustained benign load

A 60-second benign run used a deliberate workload below the policy threshold.

| Metric | Result |
|---|---:|
| Wall time | 60.036 s |
| Generated frames | 8,500 |
| Gateway RX / forwarded | 8,500 / 8,500 |
| Protected-side capture | 8,500 |
| Delivery ratio | **100.000%** |
| Input workload | 141.58 frames/s |
| Gateway CPU | **0.47% of one CPU core** |
| RSS before / after | 12,976 / 13,408 kB |
| Temperature before / after | 41.7 / 42.2 °C |
| New undervoltage events during this individual run | 0 |
| ML alerts | 0 |
| Rate-limited frames | 0 |

This is a sustained forwarding validation, not a maximum-throughput claim.

## 5. Virtual forwarding latency

A 1,000-frame same-host virtual SocketCAN test measured elapsed time from the sender timestamp immediately before `vcan0` send to receipt from `vcan1`.

| Metric | Result |
|---|---:|
| Sent / received | 1,000 / 1,000 |
| Loss | 0 |
| Mean | **46.17 µs** |
| P50 | **38.56 µs** |
| P95 | **76.39 µs** |
| P99 | **120.41 µs** |
| Minimum | 35.16 µs |
| Maximum | 638.52 µs |

These numbers include the virtual host/socket path but exclude physical transceivers, arbitration, wiring, and HIL delay.

## 6. DoS / deterministic rate limiting

A fixed-ID `0x130` stream was generated at about 1 ms spacing.

| Metric | Result |
|---|---:|
| Generated / gateway RX | 10,000 / 10,000 |
| Input workload | **944.31 frames/s** |
| Forwarded | 1,926 |
| Rate-limited | **8,074** |
| Suppression ratio | **80.74%** |
| Gateway CPU | **2.27% of one CPU core** |
| RSS before / after | 13,024 / 13,472 kB |
| Temperature before / after | 42.2 / 41.1 °C |
| New undervoltage events during this individual run | 0 |

The result demonstrates deterministic rate limiting in a synthetic vCAN stress test. It is not a physical-CAN bus-capacity measurement.

## 7. Hybrid-v4 compute latency

The benchmark included construction of an eight-frame specialist window plus Hybrid-v4 evaluation.

| Specialist | Mean | P50 | P95 | P99 |
|---|---:|---:|---:|---:|
| RPM | **66.43 µs** | 66.30 µs | 66.92 µs | 69.89 µs |
| Gear | **66.80 µs** | 66.68 µs | 67.24 µs | 70.09 µs |

This is compute latency after frames are available. It is separate from the model's intentional 100 ms observation window.

## 8. Controlled live ML test

The live raw SocketCAN test used four independent windows: RPM normal, RPM attack, Gear normal, Gear attack.

Latest rerun after SD-card filesystem repair:

```text
RPM attack  -> ML_RPM
probability 0.995995 > threshold 0.945376

Gear attack -> ML_GEAR
probability 0.999640 > threshold 0.931490

Protected side: 32 / 32 frames
```

Gateway policy behavior remained:

```text
ML-only anomaly = ALERT_ONLY
```

Therefore the ML specialist generated alerts while frames remained forwarded; ML did not directly block safety-critical traffic.

## 9. POC software readiness

Verified on the Raspberry Pi:

- Wi-Fi connected to `AutoShield-NothingPhone`
- Internet and DNS operational
- SSH active
- Avahi/mDNS active
- `autoshield-vcan.service` enabled and active
- `vcan0` and `vcan1` present and UP
- production dashboard build available
- AutoShield dashboard/API user service enabled at boot
- `/api/health` returns status `ok`
- Desktop Commander Remote user service prepared for automatic boot recovery
- POC helper scripts:
  - `tools/poc_preflight.sh`
  - `tools/poc_demo.sh`

Dashboard URL on the current hotspot assignment:

```text
http://10.190.216.221:8000/
```

The DHCP address may change on another network.

## 10. Power integrity warning

The current boot has recorded transient undervoltage events and reports:

```text
throttled=0x50000
```

At 23:02 IST, four undervoltage events had been recorded during this boot. Individual events normalized within seconds and normal operating temperatures remained in the mid-40 °C range, but the sticky flag means this boot is **not acceptable for final jury performance certification**.

Before recording final performance numbers:

1. use a known-good Raspberry Pi 5 5 V / 5 A supply and cable,
2. connect directly to a reliable wall outlet,
3. remove unnecessary USB loads,
4. cold-boot the Pi,
5. require `vcgencmd get_throttled` to remain `0x0`,
6. rerun the benchmark set.

## 11. Defensible showcase claims

Safe claims from the current evidence:

- AutoShield Hybrid-v4 is running locally on a Raspberry Pi 5.
- Live virtual SocketCAN traffic flows through `vcan0 -> gateway -> vcan1`.
- The recovered B200 feature semantics matched the live Pi feature extractor on the parity corpus.
- A controlled 1,000-frame benign vCAN test forwarded 1,000/1,000 frames.
- A 60-second 8,500-frame benign vCAN run forwarded 100%.
- A synthetic fixed-ID DoS test rate-limited 80.74% of 10,000 input frames according to the configured policy.
- Controlled RPM and Gear attack windows triggered the intended ML specialists while remaining ALERT_ONLY.
- Measured virtual forwarding latency had a P50 of 38.56 µs and P99 of 120.41 µs in the tested vCAN environment.

Do **not** describe these measurements as physical-CAN/HIL performance, production certification, zero-loss guarantees outside the tested workloads, or final performance data while the power-history flag is non-zero.
