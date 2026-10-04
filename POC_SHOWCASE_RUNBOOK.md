# AutoShield Edge AI — POC Showcase Runbook

This runbook is for the Raspberry Pi 5 virtual SocketCAN POC on branch `pi-vcan-integration`.

## Before the jury demo

Power the Pi from a known-good 5 V / 5 A Raspberry Pi 5 supply and a reliable wall outlet. After boot:

```bash
cd ~/autoshield
./tools/poc_preflight.sh
```

For a final-performance demo, `vcgencmd get_throttled` should remain `throttled=0x0`. If it is not zero, the software demo can still run, but do not present that boot as final benchmark evidence.

## Dashboard

The dashboard/API service is configured to start automatically for user `suriya`.

Check it with:

```bash
systemctl --user status autoshield-dashboard.service --no-pager
curl http://127.0.0.1:8000/api/health
```

Open from a laptop on the same network:

```text
http://<PI_IP>:8000/
```

Get the Pi address with:

```bash
hostname -I
```

## Live vCAN gateway

Start the dashboard and Hybrid-v4 live gateway:

```bash
cd ~/autoshield
./tools/poc_demo.sh start
```

Check status:

```bash
./tools/poc_demo.sh status
```

Watch gateway decisions:

```bash
./tools/poc_demo.sh logs
```

Stop only the gateway:

```bash
./tools/poc_demo.sh stop
```

## Controlled live ML demonstration

With the gateway running:

```bash
cd ~/autoshield
./tools/poc_demo.sh ml-test
```

Expected evidence:

- RPM normal window: no ML alert
- RPM attack window: `ML_RPM`
- Gear normal window: no ML alert
- Gear attack window: `ML_GEAR`
- ML-only anomaly remains `ALERT_ONLY`

To confirm the gateway output:

```bash
./tools/poc_demo.sh logs
```

## Protected-side monitoring

In another Pi SSH terminal:

```bash
candump vcan1
```

This is the protected side of the virtual gateway topology.

## Deterministic DoS demonstration

Start the gateway first, then generate a fixed-ID flood from another terminal:

```bash
cangen vcan0 -I 130 -L 8 -g 1
```

Stop the sender with Ctrl+C.

The gateway should produce `RATE_LIMIT_EXCEEDED` evidence and rate-limit traffic above the configured per-window policy.

Do not quote this as physical CAN throughput; vCAN is a Linux software loopback environment.

## Recovery commands

Dashboard:

```bash
systemctl --user restart autoshield-dashboard.service
```

Gateway:

```bash
systemctl --user restart autoshield-gateway.service
```

vCAN:

```bash
systemctl status autoshield-vcan.service --no-pager
ip -brief link show vcan0
ip -brief link show vcan1
```

Remote access:

```bash
systemctl --user status desktop-commander-remote.service --no-pager
systemctl status ssh --no-pager
systemctl status avahi-daemon --no-pager
```

Network:

```bash
nmcli -t -f DEVICE,STATE,CONNECTION device status
hostname -I
ip route
```

## Jury-safe wording

Use:

> AutoShield detects locally, decides safely, and defends at the edge. The current Raspberry Pi 5 POC uses deterministic CAN policy checks together with temporal Hybrid-v4 ML evidence. ML-only anomalies remain alert-only; deterministic policy controls enforcement.

Do not claim:

- production certification,
- ISO/SAE or UNECE compliance,
- zero-day detection,
- 100% security,
- physical CAN/HIL performance until the dual-CAN physical prototype is validated,
- final benchmark numbers from a boot that has a non-zero Raspberry Pi throttle/undervoltage history.
