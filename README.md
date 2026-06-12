# Rootkit Defense Agent

Solution defensive de surveillance, detection, quarantaine et preservation de preuves pour les suspicions de rootkits Linux.

## Installation Ubuntu

Apres clonage du repository sur une machine Ubuntu:

```bash
git clone https://github.com/hidaya0404/rootkit-defense-agent.git
cd rootkit-defense-agent
git switch dev
sudo ./install.sh
```

Le script installe l'outil dans `/opt/rootrap`, cree un environnement Python isole, installe la commande systeme `rootrap`, demarre l'agent Linux et expose le dashboard web.

Par defaut, l'interface est disponible sur:

```text
http://127.0.0.1:8081/
http://<IP_DE_LA_MACHINE_UBUNTU>:8081/
```

Commandes principales:

```bash
rootrap status
rootrap url
rootrap restart
rootrap logs ui
rootrap logs agent
rootrap quarantine list
rootrap quarantine demo
rootrap simulate-rootkit --scenario full --quarantine
```

La commande `roottrap` reste disponible comme alias de compatibilite, mais le nom officiel du produit est `rootrap`.

