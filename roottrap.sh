#!/bin/bash
# Commande globale RootTrap

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOCAL_IP=$(hostname -I | awk '{print $1}')

case "$1" in

  start)
    echo -e "${YELLOW}Démarrage de RootTrap...${NC}"
    systemctl start roottrap-agent
    systemctl start roottrap-backend
    echo -e "${GREEN}✅ RootTrap démarré${NC}"
    echo -e "Interface : ${BLUE}http://$LOCAL_IP:8080${NC}"
    ;;

  stop)
    echo -e "${YELLOW}Arrêt de RootTrap...${NC}"
    systemctl stop roottrap-agent
    systemctl stop roottrap-backend
    echo -e "${RED}⏹ RootTrap arrêté${NC}"
    ;;

  restart)
    systemctl restart roottrap-agent
    systemctl restart roottrap-backend
    echo -e "${GREEN}✅ RootTrap redémarré${NC}"
    ;;

  status)
    echo ""
    echo -e "${BLUE}=== RootTrap Status ===${NC}"
    echo ""
    echo -n "  Agent   : "
    systemctl is-active roottrap-agent &>/dev/null \
      && echo -e "${GREEN}✅ actif${NC}" \
      || echo -e "${RED}❌ inactif${NC}"

    echo -n "  Backend : "
    systemctl is-active roottrap-backend &>/dev/null \
      && echo -e "${GREEN}✅ actif${NC}" \
      || echo -e "${RED}❌ inactif${NC}"

    echo ""
    ALERTS=$(wc -l < /opt/roottrap/logs/pending_alerts.jsonl 2>/dev/null || echo 0)
    echo -e "  Alertes générées : ${YELLOW}$ALERTS${NC}"
    echo -e "  Interface : ${BLUE}http://$LOCAL_IP:8080${NC}"
    echo ""
    ;;

  logs)
    echo -e "${BLUE}=== Logs Agent ===${NC}"
    journalctl -u roottrap-agent -f
    ;;

  alerts)
    echo -e "${BLUE}=== Alertes ===${NC}"
    cat /opt/roottrap/logs/pending_alerts.jsonl | python3 -m json.tool
    ;;

  uninstall)
    echo -e "${RED}Désinstallation de RootTrap...${NC}"
    systemctl stop roottrap-agent roottrap-backend
    systemctl disable roottrap-agent roottrap-backend
    rm /etc/systemd/system/roottrap-agent.service
    rm /etc/systemd/system/roottrap-backend.service
    rm /usr/local/bin/roottrap
    rm -rf /opt/roottrap
    systemctl daemon-reload
    echo -e "${GREEN}✅ RootTrap désinstallé${NC}"
    ;;

  *)
    echo ""
    echo -e "${BLUE}RootTrap — Rootkit Defense Agent${NC}"
    echo ""
    echo "Usage : roottrap [commande]"
    echo ""
    echo "Commandes :"
    echo "  start      → démarrer les services"
    echo "  stop       → arrêter les services"
    echo "  restart    → redémarrer"
    echo "  status     → état des services"
    echo "  logs       → voir les logs en direct"
    echo "  alerts     → voir les alertes"
    echo "  uninstall  → désinstaller RootTrap"
    echo ""
    ;;
esac
