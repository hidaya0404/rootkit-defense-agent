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

Il demarre aussi `rootrap-m2-worker.service`, qui automatise la liaison:

```text
M4 /api/alerts?status=ARTIFACT_READY
  -> M2 telecharge l'artefact
  -> M2 met en quarantaine
  -> M2 verifie les hash
  -> M2 genere manifest.json
  -> M2 POST /api/quarantine/manifest vers M4
  -> M3 peut prendre l'artefact via /api/quarantine/ready
```

Les donnees affichees par defaut sont propres a la machine installee:

```text
/var/lib/rootrap      donnees runtime, quarantaine, rapports locaux
/var/log/rootrap      logs agent et alertes locales
/etc/rootrap          configuration systeme
```

Le dashboard ne copie pas les anciens resultats du repository. Il garde les checks M4 reels, mais n'importe pas automatiquement les anciens rapports distants dans l'affichage local. Pour une demo d'integration qui doit afficher aussi les donnees distantes M4:

```bash
sudo ROOTRAP_ENABLE_REMOTE_DASHBOARD_DATA=1 ./install.sh
```

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
rootrap logs m2
rootrap m2-once
rootrap diagnose
rootrap quarantine list
rootrap quarantine demo
rootrap simulate-rootkit --scenario full
```

La commande `roottrap` reste disponible comme alias de compatibilite, mais le nom officiel du produit est `rootrap`.

