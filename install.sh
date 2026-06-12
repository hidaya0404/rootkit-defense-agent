#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="RootRAP"
INSTALL_DIR="${ROOTRAP_INSTALL_DIR:-/opt/rootrap}"
STATE_DIR="${ROOTRAP_STORAGE_ROOT:-/var/lib/rootrap}"
LOG_DIR="${ROOTRAP_LOG_DIR:-/var/log/rootrap}"
CONFIG_DIR="${ROOTRAP_CONFIG_DIR:-/etc/rootrap}"
UI_HOST="${ROOTRAP_HOST:-0.0.0.0}"
UI_PORT="${ROOTRAP_PORT:-8081}"
M4_URL="${ROOTKIT_DEFENSE_M4_URL:-https://exp-queens-patterns-customs.trycloudflare.com}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
  echo -e "${BLUE}[${APP_NAME}]${NC} $*"
}

ok() {
  echo -e "${GREEN}[OK]${NC} $*"
}

warn() {
  echo -e "${YELLOW}[WARN]${NC} $*"
}

fail() {
  echo -e "${RED}[ERROR]${NC} $*" >&2
  exit 1
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
ROOTKIT_DEFENSE_M4_URL=$M4_URL
PYTHONPATH=$INSTALL_DIR
PYTHONUNBUFFERED=1
EOF
  chmod 0644 "$CONFIG_DIR/rootrap.env"
}

install_packages() {
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
    "$src"/ "$INSTALL_DIR"/
  ok "Project copied"
}

install_python_env() {
  log "Creating Python virtual environment..."
  python3 -m venv "$INSTALL_DIR/.venv"
  "$INSTALL_DIR/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
  "$INSTALL_DIR/.venv/bin/python" -m pip install -e "$INSTALL_DIR[api]"
  ok "Python environment installed"
}

generate_baselines() {
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
  log "Installing systemd services..."

  systemctl stop roottrap-agent.service roottrap-backend.service 2>/dev/null || true
  systemctl disable roottrap-agent.service roottrap-backend.service 2>/dev/null || true

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

  systemctl daemon-reload
  systemctl enable rootrap-ui.service rootrap-agent.service >/dev/null
  systemctl restart rootrap-ui.service
  systemctl restart rootrap-agent.service
  ok "Services installed and started"
}

install_command() {
  log "Installing rootrap command..."
  install -m 0755 "$INSTALL_DIR/rootrap.sh" /usr/local/bin/rootrap
  ln -sf /usr/local/bin/rootrap /usr/local/bin/roottrap
  ok "Command installed: rootrap"
}

print_summary() {
  local ip
  ip="$(local_ip)"
  echo ""
  echo -e "${GREEN}========================================${NC}"
  echo -e "${GREEN} ${APP_NAME} installation completed${NC}"
  echo -e "${GREEN}========================================${NC}"
  echo ""
  echo "Dashboard:"
  echo -e "  Local:   ${BLUE}http://127.0.0.1:${UI_PORT}/${NC}"
  if [ -n "$ip" ]; then
    echo -e "  Network: ${BLUE}http://${ip}:${UI_PORT}/${NC}"
  fi
  echo ""
  echo "Useful commands:"
  echo "  rootrap status"
  echo "  rootrap url"
  echo "  rootrap logs ui"
  echo "  rootrap logs agent"
  echo "  rootrap restart"
  echo "  rootrap quarantine demo"
  echo ""
}

main() {
  require_root
  require_ubuntu_like
  install_packages
  copy_project
  write_env_file
  install_python_env
  generate_baselines
  install_command
  install_systemd_units
  print_summary
}

main "$@"
