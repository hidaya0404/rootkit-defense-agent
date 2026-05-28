# Rootkit Defense Agent

Solution defensive de surveillance, detection, quarantaine et preservation de preuves pour les suspicions de rootkits Linux.

## Modules

```text
agent/                 Agent de surveillance Linux
shared/                Configuration et schemas d'alertes
evidence_quarantine/   Evidence & Quarantine Manager
docs/                  Guides d'architecture, demo et soutenance
schemas/               Schemas JSON de la quarantaine
web/                   Maquette de page Quarantaine
tests/                 Tests agent + quarantaine
```

## Partie Membre 2

Le module `evidence_quarantine` correspond a la partie **Isolation, Quarantaine et Collecte des Preuves**.

Il transforme une alerte rootkit en dossier de preuve :

```text
Alerte recue
-> validation de l'artefact
-> classification rootkit
-> collecte metadata forensic
-> hash avant copie
-> copie en quarantaine
-> hash apres copie
-> verification d'integrite
-> audit log
-> manifest / chain of custody
-> pret pour sandbox, IOC et reporting
```

Pour chaque alerte, il genere :

```text
artifact.bin
metadata.json
hashes.json
audit.log
manifest.json
```

## Simulation rootkit benigne

Le projet ne contient pas de vrai rootkit. Pour respecter le cadre ethique, le simulateur cree uniquement des artefacts benins qui ressemblent a des traces rootkit Linux :

```text
rk_demo.ko          -> module kernel suspect
ld.so.preload       -> hook userland suspect
rk-update.service   -> persistence systemd suspecte
cron/root           -> persistence cron suspecte
.rk_stage           -> payload cache suspect
usr/bin/ps          -> remplacement de binaire systeme suspect
```

Ces artefacts sont crees dans un dossier de lab, jamais dans les vrais chemins systeme.

## Commandes utiles

Lancer une demo simple :

```bash
python -m evidence_quarantine --storage-root ./runtime/rootkit-defense demo
```

Lancer la simulation complete avec quarantaine :

```bash
python -m evidence_quarantine --storage-root ./runtime/rootkit-defense simulate-rootkit --scenario full --quarantine
```

Victime equipee de notre detecteur de lab :

```bash
python -m evidence_quarantine --storage-root ./runtime/victim-storage lab-detect --alerts-file ./runtime/rootkit-defense/lab-victim/alerts.json
```

## Tests

```bash
python -m unittest discover -s tests
```

Avec pytest si disponible :

```bash
pytest
```

## Documentation

- `docs/architecture.md`
- `docs/rootkit_lab_simulator.md`
- `docs/attacker_victim_control_demo.md`
- `docs/security_policy.md`
- `docs/soutenance.md`

## Message de soutenance

> Ma partie preserve les preuves liees aux suspicions de rootkits Linux. Elle ne supprime pas et n'execute pas l'artefact. Elle le valide, le classe, le copie en quarantaine, verifie son integrite, journalise toutes les actions et produit un dossier exploitable par la sandbox, les IOC et le rapport final.
