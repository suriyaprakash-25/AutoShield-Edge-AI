#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}"

usage() {
  echo "Usage: $0 {start|stop|status|ml-test|logs}"
}

case "${1:-}" in
  start)
    mkdir -p "$HOME/.local/state/autoshield"
    : > "$HOME/.local/state/autoshield/gateway.log"
    systemctl --user start autoshield-dashboard.service
    systemctl --user start autoshield-gateway.service
    sleep 1
    echo "Dashboard: http://$(hostname -I | awk '{print $1}'):8000/"
    echo "Gateway:   $(systemctl --user is-active autoshield-gateway.service)"
    ;;
  stop)
    systemctl --user stop autoshield-gateway.service || true
    echo "Gateway stopped; dashboard remains available."
    ;;
  status)
    echo "Dashboard: $(systemctl --user is-active autoshield-dashboard.service 2>/dev/null || true)"
    echo "Gateway:   $(systemctl --user is-active autoshield-gateway.service 2>/dev/null || true)"
    echo "vcan0:     $(ip -brief link show vcan0 2>/dev/null || echo missing)"
    echo "vcan1:     $(ip -brief link show vcan1 2>/dev/null || echo missing)"
    ;;
  ml-test)
    systemctl --user is-active --quiet autoshield-gateway.service || {
      echo "Gateway is not active. Run: $0 start"
      exit 1
    }
    cd "$ROOT"
    source .venv/bin/activate
    python tools/live_ml_can_test.py
    ;;
  logs)
    tail -n 80 "$HOME/.local/state/autoshield/gateway.log" 2>/dev/null || true
    ;;
  *)
    usage
    exit 2
    ;;
esac
