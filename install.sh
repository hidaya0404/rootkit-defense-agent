#!/bin/bash
# =======================================
#   RootTrap — Installation
# =======================================

set -e  # arrêter si erreur

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="/opt/roottrap"
SERVICE_USER="root"

echo ""
echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}   RootTrap — Rootkit Defense Agent   ${NC}"
echo -e "${BLUE}=======================================${NC}"
echo ""

# Vérifier root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Lance ce script en root : sudo ./install.sh${NC}"
    exit 1
fi

# Vérifier Ubuntu/Debian
if ! command -v apt &> /dev/null; then
    echo -e "${RED}❌ Ce script nécessite Ubuntu/Debian${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/6] Installation des dépendances...${NC}"
apt update -q
apt install -y python3 python3-pip git curl net-tools \
               inotify-tools auditd python3-venv

pip3 install psutil watchdog requests flask flask-cors \
             --break-system-packages \
             --ignore-installed blinker werkzeug

echo -e "${GREEN}✅ Dépendances installées${NC}"

echo -e "${YELLOW}[2/6] Copie des fichiers...${NC}"
mkdir -p $INSTALL_DIR
cp -r . $INSTALL_DIR
mkdir -p $INSTALL_DIR/logs
mkdir -p $INSTALL_DIR/artifacts
mkdir -p $INSTALL_DIR/evidence_quarantine
echo -e "${GREEN}✅ Fichiers copiés dans $INSTALL_DIR${NC}"

echo -e "${YELLOW}[3/6] Génération des baselines...${NC}"
python3 << 'PYEOF'
import sys, os, hashlib, json
sys.path.insert(0, '/opt/roottrap')

# Kernel baseline
with open('/proc/modules') as f:
    modules = [l.split()[0] for l in f]
with open('/opt/roottrap/shared/kernel_modules_baseline.txt', 'w') as f:
    f.write('\n'.join(modules))
print(f"  Kernel : {len(modules)} modules")

# File baseline
files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/crontab']
baseline = {}
for path in files:
    if os.path.isfile(path):
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            h.update(f.read())
        baseline[path] = h.hexdigest()
with open('/opt/roottrap/shared/file_baseline.json', 'w') as f:
    json.dump(baseline, f, indent=2)
print(f"  Fichiers : {len(baseline)} fichiers")
PYEOF
echo -e "${GREEN}✅ Baselines générées${NC}"

echo -e "${YELLOW}[4/6] Installation du service agent...${NC}"
cat > /etc/systemd/system/roottrap-agent.service << 'SVCEOF'
[Unit]
Description=RootTrap Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/roottrap
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 /opt/roottrap/agent/main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable roottrap-agent
systemctl start roottrap-agent
echo -e "${GREEN}✅ Agent démarré${NC}"

echo -e "${YELLOW}[5/6] Installation du service backend...${NC}"
cat > /etc/systemd/system/roottrap-backend.service << 'SVCEOF'
[Unit]
Description=RootTrap Backend
After=network.target roottrap-agent.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/roottrap
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 /opt/roottrap/backend/api.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable roottrap-backend
systemctl start roottrap-backend
echo -e "${GREEN}✅ Backend démarré${NC}"

echo -e "${YELLOW}[6/6] Installation de la commande roottrap...${NC}"
cp roottrap.sh /usr/local/bin/roottrap
chmod +x /usr/local/bin/roottrap
echo -e "${GREEN}✅ Commande roottrap installée${NC}"

# Récupérer l'IP locale
LOCAL_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}=======================================${NC}"
echo -e "${GREEN}   ✅ Installation terminée !          ${NC}"
echo -e "${GREEN}=======================================${NC}"
echo ""
echo -e "  Interface disponible sur :"
echo -e "  ${BLUE}http://localhost:8080${NC}"
echo -e "  ${BLUE}http://$LOCAL_IP:8080${NC}"
echo ""
echo -e "  Commandes utiles :"
echo -e "  ${YELLOW}roottrap status${NC}   → état des services"
echo -e "  ${YELLOW}roottrap logs${NC}     → voir les logs"
echo -e "  ${YELLOW}roottrap stop${NC}     → arrêter"
echo -e "  ${YELLOW}roottrap start${NC}    → démarrer"
echo ""
