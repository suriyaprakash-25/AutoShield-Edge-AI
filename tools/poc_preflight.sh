#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}"

fail=0
warn=0

ok()   { printf 'PASS  %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*"; fail=1; }
note() { printf 'WARN  %s\n' "$*"; warn=1; }

echo "AutoShield Edge AI — POC Preflight"
echo "=================================="
echo "Time : $(date -Is)"
echo "Host : $(hostname)"
echo "IP   : $(hostname -I | xargs)"
echo

if nmcli -t -f DEVICE,STATE device status 2>/dev/null | grep -q '^wlan0:connected$'; then
  conn="$(nmcli -g GENERAL.CONNECTION device show wlan0 2>/dev/null || true)"
  ok "Wi-Fi connected ($conn)"
else
  bad "Wi-Fi is not connected"
fi

if ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
  ok "Internet IP connectivity"
else
  note "Internet ping failed"
fi

if getent hosts github.com >/dev/null 2>&1; then ok "DNS resolution"; else note "DNS resolution failed"; fi
systemctl is-active --quiet ssh && ok "SSH service active" || bad "SSH service inactive"
systemctl is-active --quiet avahi-daemon && ok "mDNS/Avahi active" || note "mDNS/Avahi inactive"

systemctl is-active --quiet autoshield-vcan.service && ok "vCAN boot service active" || bad "vCAN boot service inactive"
ip link show vcan0 >/dev/null 2>&1 && ok "vcan0 present" || bad "vcan0 missing"
ip link show vcan1 >/dev/null 2>&1 && ok "vcan1 present" || bad "vcan1 missing"

if systemctl --user is-active --quiet autoshield-dashboard.service; then
  ok "Dashboard/API user service active"
else
  bad "Dashboard/API user service inactive"
fi

if curl -fsS --max-time 2 http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
  ok "Dashboard/API health endpoint"
else
  bad "Dashboard/API health endpoint unavailable"
fi

cd "$ROOT"
branch="$(git branch --show-current 2>/dev/null || true)"
echo "INFO  Git branch: $branch"
if git diff --quiet -- . ':!RPI5_PERFORMANCE_VALIDATION_2026-10-04.md' 2>/dev/null; then
  ok "Tracked source tree has no unstaged modifications"
else
  note "Tracked source tree has modifications"
fi

if command -v vcgencmd >/dev/null 2>&1; then
  temp="$(vcgencmd measure_temp 2>/dev/null || true)"
  throttled="$(vcgencmd get_throttled 2>/dev/null || true)"
  echo "INFO  $temp"
  echo "INFO  $throttled"
  if [ "$throttled" = "throttled=0x0" ]; then
    ok "No power/throttle flags since boot"
  else
    note "Power/throttle history is non-zero; do not present final performance numbers from this boot"
  fi
fi

uv="$(dmesg 2>/dev/null | grep -ci 'Undervoltage detected' || true)"
echo "INFO  Undervoltage events this boot: $uv"
if [ "$uv" -gt 0 ] 2>/dev/null; then
  note "Undervoltage events detected — check PSU/cable before jury benchmark"
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "RESULT: NOT READY — critical software check failed."
  exit 1
elif [ "$warn" -ne 0 ]; then
  echo "RESULT: SOFTWARE READY WITH WARNINGS."
  exit 0
else
  echo "RESULT: READY."
  exit 0
fi
