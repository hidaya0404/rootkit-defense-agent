# Architecture du module

## Objectif

Le module **Evidence & Quarantine Manager** transforme une alerte de securite en dossier de preuve exploitable.

Il recoit un chemin suspect depuis le moteur de detection, valide ce chemin, preserve les metadonnees, copie l'artefact en quarantaine, verifie son integrite, journalise chaque action et prepare un handoff propre vers la sandbox.

## Composants

```text
quarantine_manager.py
  Orchestrateur principal du workflow.

quarantine_policy.py
  Validation defensive du chemin suspect.

hash_service.py
  Calcul MD5, SHA1, SHA256 en streaming.

integrity_verifier.py
  Comparaison des empreintes avant et apres copie.

metadata_collector.py
  Collecte des metadonnees forensic.

rootkit_classifier.py
  Classification defensive des artefacts lies aux rootkits Linux :
  module kernel, preload hook, systemd/cron persistence, shared library hook,
  hidden payload, temporary executable payload.

audit_logger.py
  Journalisation globale et locale.

repository.py
  Index JSON exploitable par l'API et l'interface web.

models.py
  Contrats de donnees internes.

api.py
  API FastAPI optionnelle.

cli.py
  Interface ligne de commande pour demo et tests.
```

## Workflow

```text
1. ALERT_RECEIVED
2. POLICY_VALIDATED ou POLICY_REJECTED
3. METADATA_COLLECTED
4. HASH_BEFORE_COPY
5. ARTIFACT_COPIED
6. HASH_AFTER_COPY
7. INTEGRITY_VERIFIED ou INTEGRITY_FAILED
8. EVIDENCE_PACKAGE_CREATED
9. READY_FOR_ANALYSIS
```

## Dossier de preuve

```text
quarantine/ALT-2026-000001/
├── artifact.bin
├── metadata.json
├── hashes.json
├── audit.log
└── manifest.json
```

### artifact.bin

Copie non destructive de l'artefact suspect. Le nom est standardise pour eviter les noms dangereux ou trompeurs. Le nom original reste conserve dans `metadata.json`.

### metadata.json

Contient les metadonnees forensic :

- chemin original ;
- chemin en quarantaine ;
- type de fichier ;
- taille ;
- permissions ;
- UID/GID ;
- dates ;
- raison de detection ;
- statut ;
- niveau de risque ;
- resultat d'integrite.
- profil rootkit : categorie, techniques suspectees, justification, mapping MITRE.

## Specialisation rootkits Linux

Le module Membre 2 ne detecte pas le rootkit lui-meme. Cette detection appartient au Membre 1. Par contre, lorsqu'un artefact arrive dans la quarantaine, il est classe selon des patterns rootkit defensifs :

```text
kernel_module_rootkit_suspect      -> fichier .ko ou chemin /lib/modules
userland_preload_hook_suspect      -> ld.so.preload
kernel_module_persistence_suspect  -> modules-load.d ou modprobe.d
systemd_persistence_suspect        -> fichier .service ou systemd
cron_persistence_suspect           -> cron ou spool cron
shared_library_hook_suspect        -> bibliotheque .so
hidden_payload_suspect             -> fichier cache dans /tmp, /var/tmp ou /dev/shm
temporary_executable_payload       -> executable depose en repertoire temporaire
system_binary_tampering_suspect    -> binaire systeme remplace, ex: ps, ls, netstat
```

Cette classification aide les membres 3 et 4 a choisir l'analyse suivante : sandbox, readelf, strings, YARA, comparaison de hash avec un systeme propre ou correlation avec les mecanismes de persistance.

### hashes.json

Contient les empreintes avant et apres copie :

- MD5 ;
- SHA1 ;
- SHA256 ;
- resultat de comparaison.

### audit.log

Journal chronologique des actions realisees sur l'alerte.

### manifest.json

Decrit le package de preuve et sa chain of custody.

## Etats

```text
RECEIVED
VALIDATED
HASHED
QUARANTINED
INTEGRITY_VERIFIED
READY_FOR_ANALYSIS
INTEGRITY_FAILED
REJECTED
FAILED
```

## Integration avec les autres membres

### Entree depuis Membre 1

Le module attend un evenement d'alerte contenant au minimum :

```json
{
  "alert_id": "ALT-2026-000001",
  "artifact_path": "/tmp/suspicious.sh",
  "detection_reason": "Executable file created in suspicious directory",
  "risk_level": "HIGH"
}
```

### Sortie vers Membre 3

Le module expose un handoff sandbox :

```json
{
  "alert_id": "ALT-2026-000001",
  "artifact_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/artifact.bin",
  "sha256": "...",
  "manifest_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/manifest.json",
  "handoff_status": "READY_FOR_SANDBOX"
}
```

### Sortie vers Membre 4

Les fichiers `metadata.json`, `hashes.json` et `manifest.json` alimentent l'analyse statique, les IOC et le reporting.
