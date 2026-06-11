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
  "artifact_id": "ART-ALT-2026-000001",
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

## GET /quarantine/{alert_id}/manifest

Retourne le manifest compatible avec le backend M4 :

```json
{
  "artifact_id": "ART-ALT-2026-000001",
  "alert_id": "ALT-2026-000001",
  "timestamp": "2026-05-28T19:22:07Z",
  "filename": "rk_demo.ko",
  "sha256": "...",
  "md5": "...",
  "sha1": "...",
  "hashes": {
    "md5": "...",
    "sha1": "...",
    "sha256": "..."
  },
  "original_path": "/tmp/rk_demo.ko",
  "quarantine_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/artifact.bin",
  "stored_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/artifact.bin",
  "metadata_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/metadata.json",
  "hashes_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/hashes.json",
  "manifest_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/manifest.json",
  "backend_manifest_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/backend_manifest.json",
  "rootkit_category": "kernel_module_rootkit_suspect",
  "status": "READY_FOR_ANALYSIS",
  "source_alert_status": "ARTIFACT_READY",
  "integrity_verified": true,
  "ready_for_sandbox": true,
  "download_url": "/quarantine/ALT-2026-000001/download",
  "created_at": "2026-05-28T19:22:07Z"
}
```

## GET /quarantine/{alert_id}/download

Telecharge `artifact.bin` depuis la quarantaine.

## POST /quarantine/{alert_id}/sandbox-handoff

Retourne les informations necessaires pour le module sandbox.

```json
{
  "alert_id": "ALT-2026-000001",
  "artifact_id": "ART-ALT-2026-000001",
  "artifact_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/artifact.bin",
  "quarantine_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/artifact.bin",
  "filename": "rk_demo.ko",
  "md5": "...",
  "sha1": "...",
  "sha256": "...",
  "metadata_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/metadata.json",
  "manifest_path": "/var/lib/rootkit-defense/quarantine/ALT-2026-000001/manifest.json",
  "download_url": "/quarantine/ALT-2026-000001/download",
  "handoff_status": "READY_FOR_SANDBOX"
}
```

## CLI M2 -> Backend M4

Envoyer un manifest vers le backend M4 :

```bash
python -m evidence_quarantine --storage-root ./runtime/rootkit-defense \
  sync-manifest \
  --backend-url http://127.0.0.1:8000 \
  --ready-only
```

## CLI M4 -> M2 -> M4

Recuperer les alertes M4 dont l'artefact est pret, telecharger l'artefact, le
mettre en quarantaine, generer `backend_manifest.json`, puis poster le manifest
sur `POST /api/quarantine/manifest` :

```bash
python -m evidence_quarantine --storage-root ./runtime/rootkit-defense \
  process-backend-alerts \
  --backend-url http://127.0.0.1:8000 \
  --status ARTIFACT_READY
```

Flux attendu :

```text
GET /api/alerts?status=ARTIFACT_READY
GET /api/artifacts/{alert_id}/download
M2 quarantine + hash + metadata + audit + backend_manifest.json
POST /api/quarantine/manifest
```

Pour tester seulement la quarantaine locale sans renvoyer le manifest :

```bash
python -m evidence_quarantine --storage-root ./runtime/rootkit-defense \
  process-backend-alerts \
  --backend-url http://127.0.0.1:8000 \
  --status ARTIFACT_READY \
  --no-send-manifest
```
