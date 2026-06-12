#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="RootRAP"
ENV_FILE="${ROOTRAP_ENV_FILE:-/etc/rootrap/rootrap.env}"

if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "$SCRIPT_DIR/evidence_quarantine" ]; then
  DEFAULT_APP_DIR="$SCRIPT_DIR"
else
  DEFAULT_APP_DIR="/opt/rootrap"
fi

APP_DIR="${ROOTRAP_APP_DIR:-$DEFAULT_APP_DIR}"
STATE_DIR="${ROOTRAP_STORAGE_ROOT:-/var/lib/rootrap}"
LOG_DIR="${ROOTRAP_LOG_DIR:-/var/log/rootrap}"
HOST="${ROOTRAP_HOST:-0.0.0.0}"
PORT="${ROOTRAP_PORT:-8081}"
PYTHON_BIN="${APP_DIR}/.venv/bin/python"

if [ ! -x "$PYTHON_BIN" ]; then
  PYTHON_BIN="python3"
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

sudo_cmd() {
  if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

local_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}' \
    || hostname -I 2>/dev/null | awk '{print $1}'
}

display_host() {
  if [ "$HOST" = "0.0.0.0" ] || [ "$HOST" = "::" ]; then
    local_ip
  else
    echo "$HOST"
  fi
}

print_url() {
  local ip
  ip="$(display_host)"
  echo -e "${BOLD}${BLUE}${APP_NAME} dashboard${NC}"
  echo -e "  ${CYAN}Local   :${NC} http://127.0.0.1:${PORT}/"
  if [ -n "$ip" ] && [ "$ip" != "127.0.0.1" ]; then
    echo -e "  ${CYAN}Network :${NC} http://${ip}:${PORT}/"
  fi
}

run_evidence_quarantine() {
  cd "$APP_DIR"
  "$PYTHON_BIN" -m evidence_quarantine --storage-root "$STATE_DIR" "$@"
}

service_status() {
  local service="$1"
  if systemctl is-active --quiet "$service" 2>/dev/null; then
    echo -e "${GREEN}[✔] active${NC}"
  else
    echo -e "${RED}[✘] inactive${NC}"
  fi
}

health_check() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1 \
      && echo -e "${GREEN}[✔] dashboard API ok${NC}" \
      || echo -e "${YELLOW}[!] dashboard API not reachable locally${NC}"
  else
    echo -e "${YELLOW}[!] curl not installed; health not checked${NC}"
  fi
}

wait_health() {
  local url="http://127.0.0.1:${PORT}/api/health"
  if ! command -v curl >/dev/null 2>&1; then
    return 0
  fi
  for _ in $(seq 1 20); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

print_banner() {
  echo -e "${RED}"
  cat <<'EOF'
 ██████╗  ██████╗  ██████╗ ████████╗██████╗  █████╗ ██████╗
 ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗
 ██████╔╝██║   ██║██║   ██║   ██║   ██████╔╝███████║██████╔╝
 ██╔══██╗██║   ██║██║   ██║   ██║   ██╔══██╗██╔══██║██╔═══╝
 ██║  ██║╚██████╔╝╚██████╔╝   ██║   ██║  ██║██║  ██║██║
 ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
EOF
  echo -e "${NC}"
}

usage() {
  cat <<EOF
RootRAP - Linux rootkit defense platform

Usage:
  rootrap start              Start dashboard and agent services
  rootrap stop               Stop services
  rootrap restart            Restart services
  rootrap status             Show service and dashboard health
  rootrap url                Print dashboard IP and port
  rootrap serve              Run the dashboard in the foreground
  rootrap logs [ui|agent]    Follow service logs
  rootrap alerts             Print local M1 alerts
  rootrap quarantine <args>  Run M2 quarantine CLI commands
  rootrap demo               Create a benign demo artifact in quarantine
  rootrap simulate-rootkit   Create safe rootkit-like lab artifacts
  rootrap diagnose           Show quick troubleshooting output
  rootrap uninstall          Remove services, command and installed files

Examples:
  rootrap status
  rootrap url
  rootrap serve
  rootrap quarantine list
  rootrap quarantine demo
EOF
}

cmd="${1:-help}"
shift || true

case "$cmd" in
  start)
    sudo_cmd systemctl start rootrap-ui.service rootrap-agent.service
    if ! wait_health; then
      echo -e "${YELLOW}[!] UI service started, but local API is not reachable yet.${NC}"
      echo "    Run: rootrap logs ui"
    fi
    print_url
    ;;
  stop)
    sudo_cmd systemctl stop rootrap-ui.service rootrap-agent.service
    echo -e "${GREEN}${APP_NAME} stopped${NC}"
    ;;
  restart)
    sudo_cmd systemctl restart rootrap-ui.service rootrap-agent.service
    if ! wait_health; then
      echo -e "${YELLOW}[!] UI service restarted, but local API is not reachable yet.${NC}"
      echo "    Run: rootrap logs ui"
    fi
    print_url
    ;;
  status)
    print_banner
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  ${APP_NAME} — STATUS${NC}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════${NC}"
    echo -n "  UI service     : "
    service_status rootrap-ui.service
    echo -n "  Agent service  : "
    service_status rootrap-agent.service
    echo -n "  Health         : "
    health_check
    echo -e "  ${CYAN}App dir        :${NC} $APP_DIR"
    echo -e "  ${CYAN}Runtime data   :${NC} $STATE_DIR"
    echo -e "  ${CYAN}Logs           :${NC} $LOG_DIR"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════${NC}"
    print_url
    ;;
  url)
    print_url
    ;;
  serve|ui)
    run_evidence_quarantine ui --host "$HOST" --port "$PORT" --no-browser "$@"
    ;;
  logs)
    target="${1:-ui}"
    if [ "$target" = "agent" ]; then
      sudo_cmd journalctl -u rootrap-agent.service -f
    else
      sudo_cmd journalctl -u rootrap-ui.service -f
    fi
    ;;
  alerts)
    alerts_file="${ROOTRAP_PENDING_ALERTS_FILE:-$LOG_DIR/pending_alerts.jsonl}"
    if [ ! -s "$alerts_file" ]; then
      echo "No local alerts found at $alerts_file"
      exit 0
    fi
    cat "$alerts_file"
    ;;
  diagnose)
    echo -e "${BOLD}${BLUE}${APP_NAME} diagnostics${NC}"
    echo ""
    echo "Services:"
    systemctl --no-pager --full status rootrap-ui.service rootrap-agent.service || true
    echo ""
    echo "Listening ports:"
    ss -ltnp 2>/dev/null | grep ":${PORT}" || true
    echo ""
    echo "UI logs:"
    sudo_cmd journalctl -u rootrap-ui.service -n 40 --no-pager || true
    ;;
  quarantine)
    if [ "$#" -eq 0 ]; then
      run_evidence_quarantine --help
    else
      run_evidence_quarantine "$@"
    fi
    ;;
  demo)
    run_evidence_quarantine demo "$@"
    ;;
  simulate-rootkit)
    run_evidence_quarantine simulate-rootkit "$@"
    ;;
  open)
    url="http://127.0.0.1:${PORT}/"
    if command -v xdg-open >/dev/null 2>&1; then
      xdg-open "$url" >/dev/null 2>&1 &
    fi
    print_url
    ;;
  uninstall)
    echo -e "${YELLOW}Removing ${APP_NAME} from this machine...${NC}"
    sudo_cmd systemctl stop rootrap-ui.service rootrap-agent.service 2>/dev/null || true
    sudo_cmd systemctl disable rootrap-ui.service rootrap-agent.service 2>/dev/null || true
    sudo_cmd systemctl stop roottrap-agent.service roottrap-backend.service 2>/dev/null || true
    sudo_cmd systemctl disable roottrap-agent.service roottrap-backend.service 2>/dev/null || true
    sudo_cmd rm -f /etc/systemd/system/rootrap-ui.service /etc/systemd/system/rootrap-agent.service
    sudo_cmd rm -f /etc/systemd/system/roottrap-agent.service /etc/systemd/system/roottrap-backend.service
    sudo_cmd rm -f /usr/local/bin/rootrap /usr/local/bin/roottrap
    sudo_cmd rm -rf "$APP_DIR" "$STATE_DIR" "$LOG_DIR" /etc/rootrap
    sudo_cmd systemctl daemon-reload
    echo -e "${GREEN}${APP_NAME} removed${NC}"
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo -e "${RED}Unknown command: $cmd${NC}" >&2
    usage
    exit 2
    ;;
esac
