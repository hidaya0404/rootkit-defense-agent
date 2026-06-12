#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="RootRAP"
INSTALL_DIR="${ROOTRAP_INSTALL_DIR:-/opt/rootrap}"
STATE_DIR="${ROOTRAP_STORAGE_ROOT:-/var/lib/rootrap}"
LOG_DIR="${ROOTRAP_LOG_DIR:-/var/log/rootrap}"
CONFIG_DIR="${ROOTRAP_CONFIG_DIR:-/etc/rootrap}"
UI_HOST="${ROOTRAP_HOST:-0.0.0.0}"
UI_PORT="${ROOTRAP_PORT:-8081}"
M4_URL="${ROOTKIT_DEFENSE_M4_URL:-https://tremendous-cow-functionality-puzzles.trycloudflare.com}"
REMOTE_DATA="${ROOTRAP_ENABLE_REMOTE_DASHBOARD_DATA:-0}"
INSTALL_LOG="${ROOTRAP_INSTALL_LOG:-/var/log/rootrap-install.log}"
M2_POLL_INTERVAL="${ROOTRAP_M2_POLL_INTERVAL:-15}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log() {
  echo -e "${CYAN}[i]${NC} $*"
}

ok() {
  echo -e "${GREEN}[✔]${NC} $*"
}

warn() {
  echo -e "${YELLOW}[!]${NC} $*"
}

fail() {
  echo -e "${RED}[✘]${NC} $*" >&2
  exit 1
}

section() {
  echo ""
  echo -e "${BOLD}${CYAN}▶ $*${NC}"
  echo ""
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
        Linux Rootkit Defense Platform — Installer v1.0
EOF
  echo -e "${NC}"
}

local_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}' \
    || hostname -I 2>/dev/null | awk '{print $1}'
}

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    fail "Run this installer with sudo: sudo ./install.sh"
  fi
}

require_ubuntu_like() {
  if ! command -v apt-get >/dev/null 2>&1; then
    fail "This installer targets Ubuntu/Debian systems with apt-get."
  fi
}

repo_dir() {
  local source_dir
  source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  readlink -f "$source_dir"
}

write_env_file() {
  local ip public_base
  ip="$(local_ip)"
  public_base="${ROOTRAP_PUBLIC_BASE_URL:-}"
  if [ -z "$public_base" ] && [ -n "$ip" ]; then
    public_base="http://${ip}:${UI_PORT}"
  fi

  mkdir -p "$CONFIG_DIR"
  cat > "$CONFIG_DIR/rootrap.env" <<EOF
ROOTRAP_APP_DIR=$INSTALL_DIR
ROOTRAP_STORAGE_ROOT=$STATE_DIR
ROOTRAP_LOG_DIR=$LOG_DIR
ROOTRAP_HOST=$UI_HOST
ROOTRAP_PORT=$UI_PORT
ROOTRAP_AGENT_LOG_FILE=$LOG_DIR/agent.log
ROOTRAP_PENDING_ALERTS_FILE=$LOG_DIR/pending_alerts.jsonl
ROOTRAP_AGENT_QUARANTINE_DIR=$STATE_DIR/agent-quarantine
ROOTRAP_BASELINE_DIR=$INSTALL_DIR/shared
ROOTRAP_ENABLE_REMOTE_DASHBOARD_DATA=$REMOTE_DATA
ROOTKIT_DEFENSE_STORAGE=$STATE_DIR
ROOTKIT_DEFENSE_M4_URL=$M4_URL
ROOTRAP_M2_POLL_INTERVAL=$M2_POLL_INTERVAL
ROOTRAP_PUBLIC_BASE_URL=$public_base
PYTHONPATH=$INSTALL_DIR
PYTHONUNBUFFERED=1
EOF
  chmod 0644 "$CONFIG_DIR/rootrap.env"
}

install_packages() {
  section "Checking system prerequisites"
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    log "Detected OS: ${PRETTY_NAME:-Linux}"
  fi

  log "Installing operating-system dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y \
    ca-certificates \
    curl \
    file \
    git \
    iproute2 \
    net-tools \
    procps \
    python3 \
    python3-pip \
    python3-venv \
    rsync \
    binutils
  ok "System dependencies installed"
}

copy_project() {
  section "Installing project files"
  local src
  src="$(repo_dir)"

  mkdir -p "$INSTALL_DIR" "$STATE_DIR" "$LOG_DIR"

  if [ "$src" = "$(readlink -f "$INSTALL_DIR" 2>/dev/null || echo "$INSTALL_DIR")" ]; then
    warn "Source and install directory are the same; skipping copy."
    return
  fi

  log "Copying project to $INSTALL_DIR..."
  rsync -a --delete \
    --exclude ".git" \
    --exclude ".venv" \
    --exclude "__pycache__" \
    --exclude ".pytest_cache" \
    --exclude "runtime" \
    --exclude "handoff" \
    --exclude "logs" \
    --exclude "backend/data" \
    --exclude "artifacts" \
    --exclude "data" \
    --exclude "download" \
    --exclude "uploads" \
    --exclude "reports/generated" \
    --exclude "quarantine_zone" \
    --exclude "sandbox/results" \
    --delete-excluded \
    "$src"/ "$INSTALL_DIR"/
  ok "Project copied"
}

prepare_runtime_dirs() {
  section "Preparing machine-specific runtime"
  rm -rf \
    "$INSTALL_DIR/logs" \
    "$INSTALL_DIR/backend/data" \
    "$INSTALL_DIR/artifacts" \
    "$INSTALL_DIR/data" \
    "$INSTALL_DIR/download" \
    "$INSTALL_DIR/uploads" \
    "$INSTALL_DIR/reports/generated" \
    "$INSTALL_DIR/quarantine_zone" \
    "$INSTALL_DIR/sandbox/results"

  mkdir -p \
    "$STATE_DIR/quarantine" \
    "$STATE_DIR/audit" \
    "$STATE_DIR/reports" \
    "$STATE_DIR/sandbox/results" \
    "$STATE_DIR/agent-quarantine" \
    "$LOG_DIR"

  touch "$LOG_DIR/agent.log" "$LOG_DIR/pending_alerts.jsonl"
  chmod 0750 "$STATE_DIR" "$LOG_DIR"
  chmod 0640 "$LOG_DIR/agent.log" "$LOG_DIR/pending_alerts.jsonl"
  ok "Runtime isolated in $STATE_DIR and $LOG_DIR"
}

install_python_env() {
  section "Installing Python environment"
  log "Creating Python virtual environment..."
  python3 -m venv "$INSTALL_DIR/.venv"
  "$INSTALL_DIR/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
  "$INSTALL_DIR/.venv/bin/python" -m pip install -e "$INSTALL_DIR[api]"
  ok "Python environment installed"
}

generate_baselines() {
  section "Generating local Linux baselines"
  log "Generating local Linux baselines..."
  ROOTRAP_INSTALL_DIR="$INSTALL_DIR" "$INSTALL_DIR/.venv/bin/python" - <<'PY'
from pathlib import Path
import hashlib
import json
import os

root = Path(os.environ["ROOTRAP_INSTALL_DIR"])
shared = root / "shared"
shared.mkdir(parents=True, exist_ok=True)

modules_file = shared / "kernel_modules_baseline.txt"
try:
    modules = [line.split()[0] for line in Path("/proc/modules").read_text().splitlines() if line.strip()]
except OSError:
    modules = []
modules_file.write_text("\n".join(modules) + ("\n" if modules else ""), encoding="utf-8")

baseline = {}
for candidate in ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab"]:
    path = Path(candidate)
    if not path.is_file():
        continue
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        baseline[str(path)] = digest.hexdigest()
    except OSError:
        continue

(shared / "file_baseline.json").write_text(json.dumps(baseline, indent=2), encoding="utf-8")
print(f"kernel_modules={len(modules)} sensitive_files={len(baseline)}")
PY
  ok "Baselines generated"
}

install_systemd_units() {
  section "Installing services"
  log "Installing systemd services..."

  systemctl stop rootrap-m2-worker.service roottrap-agent.service roottrap-backend.service 2>/dev/null || true
  systemctl disable rootrap-m2-worker.service roottrap-agent.service roottrap-backend.service 2>/dev/null || true

  cat > /etc/systemd/system/rootrap-ui.service <<EOF
[Unit]
Description=RootRAP Web Dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$CONFIG_DIR/rootrap.env
ExecStart=$INSTALL_DIR/.venv/bin/python -m evidence_quarantine --storage-root $STATE_DIR ui --host $UI_HOST --port $UI_PORT --no-browser
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/rootrap-agent.service <<EOF
[Unit]
Description=RootRAP Linux Rootkit Defense Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$CONFIG_DIR/rootrap.env
ExecStart=$INSTALL_DIR/.venv/bin/python $INSTALL_DIR/agent/main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/rootrap-m2-worker.service <<EOF
[Unit]
Description=RootRAP M2 Automatic Quarantine Worker
After=network-online.target rootrap-ui.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$CONFIG_DIR/rootrap.env
ExecStart=$INSTALL_DIR/.venv/bin/python -m evidence_quarantine --storage-root $STATE_DIR auto-process-backend --backend-url $M4_URL --interval $M2_POLL_INTERVAL --status ARTIFACT_READY --public-base-url \${ROOTRAP_PUBLIC_BASE_URL}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable rootrap-ui.service rootrap-agent.service rootrap-m2-worker.service >/dev/null
  systemctl restart rootrap-ui.service
  systemctl restart rootrap-agent.service
  systemctl restart rootrap-m2-worker.service
  wait_for_dashboard
  ok "Services installed and started"
}

install_command() {
  section "Installing system command"
  log "Installing rootrap command..."
  install -m 0755 "$INSTALL_DIR/rootrap.sh" /usr/local/bin/rootrap
  ln -sf /usr/local/bin/rootrap /usr/local/bin/roottrap
  ok "Command installed: rootrap"
}

wait_for_dashboard() {
  local url="http://127.0.0.1:${UI_PORT}/api/health"
  log "Waiting for dashboard API: $url"
  for _ in $(seq 1 30); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      ok "Dashboard API is reachable"
      return 0
    fi
    sleep 1
  done

  warn "Dashboard API did not answer within 30 seconds."
  warn "Recent UI logs:"
  journalctl -u rootrap-ui.service -n 30 --no-pager || true
  fail "RootRAP UI service started but /api/health is not reachable."
}

print_summary() {
  local ip
  ip="$(local_ip)"
  echo ""
  echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  ${APP_NAME} — INSTALLED AND RUNNING${NC}"
  echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════${NC}"
  echo -e "  ${CYAN}Local URL      :${NC} http://127.0.0.1:${UI_PORT}/"
  if [ -n "$ip" ]; then
    echo -e "  ${CYAN}Network URL    :${NC} http://${ip}:${UI_PORT}/"
  fi
  echo -e "  ${CYAN}Install dir    :${NC} $INSTALL_DIR"
  echo -e "  ${CYAN}Runtime data   :${NC} $STATE_DIR"
  echo -e "  ${CYAN}Logs           :${NC} $LOG_DIR"
  echo -e "  ${CYAN}M4 backend     :${NC} $M4_URL"
  echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════${NC}"
  echo ""
  echo "Useful commands:"
  echo "  rootrap status"
  echo "  rootrap url"
  echo "  rootrap logs ui"
  echo "  rootrap logs agent"
  echo "  rootrap logs m2"
  echo "  rootrap restart"
  echo "  rootrap quarantine demo"
  echo ""
}

main() {
  print_banner
  require_root
  require_ubuntu_like
  : > "$INSTALL_LOG"
  install_packages
  copy_project
  prepare_runtime_dirs
  write_env_file
  install_python_env
  generate_baselines
  install_command
  install_systemd_units
  print_summary
}

main "$@"
