# Contrat API

## POST /quarantine

Requete :

```json
{
  "alert_id": "ALT-2026-000001",
  "artifact_path": "/tmp/suspicious.sh",
  "detection_reason": "Executable file created in suspicious directory",
  "risk_level": "HIGH",
  "detected_at": "2026-05-28T18:30:10Z",
  "source_module": "agent-file-monitor",
  "tags": ["file-monitor", "persistence-check"]
}
```

Reponse succes :

```json
{
  "success": true,
  "alert_id": "ALT-2026-000001",
  "status": "READY_FOR_ANALYSIS",
  "evidence_dir": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001",
  "artifact_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/artifact.bin",
  "metadata_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/metadata.json",
  "hashes_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/hashes.json",
  "manifest_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/manifest.json",
  "audit_log_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/audit.log",
  "errors": []
}
```

Reponse rejet :

```json
{
  "success": false,
  "alert_id": "ALT-2026-000002",
  "status": "REJECTED",
  "evidence_dir": "/var/lib/rootkit-defense/quarantine/ALT-2026-000002",
  "artifact_path": null,
  "metadata_path": null,
  "hashes_path": null,
  "manifest_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000002/manifest.json",
  "audit_log_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000002/audit.log",
  "errors": ["Artifact path does not exist"]
}
```

## GET /quarantine

Retourne l'index des dossiers de preuve.

## GET /quarantine/{alert_id}

Retourne le resume d'une alerte.

## GET /quarantine/{alert_id}/package

Retourne le resume avec `metadata`, `hashes` et `manifest`.

## POST /quarantine/{alert_id}/sandbox-handoff

Retourne les informations necessaires pour le module sandbox.

```json
{
  "alert_id": "ALT-2026-000001",
  "artifact_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/artifact.bin",
  "sha256": "...",
  "manifest_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/manifest.json",
  "handoff_status": "READY_FOR_SANDBOX"
}
```

