# Scenario de demonstration

## Objectif

Montrer que le module Membre 2 peut recevoir une alerte rootkit, isoler un faux module kernel `.ko` benin, produire un dossier de preuve et le rendre pret pour la sandbox.

## Preparation

```bash
cd evidence-quarantine-manager
PYTHONPATH=src python -m evidence_quarantine --storage-root ./runtime/rootkit-defense demo
```

Pour une demonstration plus complete avec plusieurs traces rootkit benignes :

```bash
PYTHONPATH=src python -m evidence_quarantine --storage-root ./runtime/rootkit-defense simulate-rootkit --scenario full --quarantine
```

## Etapes a montrer au jury

1. L'agent ou le simulateur cree une alerte sur `rk_demo.ko`.
2. Le module recoit le chemin de l'artefact.
3. La policy valide le fichier.
4. Les metadonnees sont collectees.
5. Les hash sont calcules avant la copie.
6. L'artefact est copie dans la quarantaine.
7. Les hash sont recalcules apres copie.
8. L'integrite est verifiee.
9. Le dossier de preuve est genere.
10. L'alerte devient `READY_FOR_ANALYSIS`.

## Fichiers a ouvrir

```text
runtime/rootkit-defense/quarantine/ALT-DEMO-000001/metadata.json
runtime/rootkit-defense/quarantine/ALT-DEMO-000001/hashes.json
runtime/rootkit-defense/quarantine/ALT-DEMO-000001/audit.log
runtime/rootkit-defense/quarantine/ALT-DEMO-000001/manifest.json
```

## Phrase courte pendant la demo

> Ici, on voit que le module ne supprime pas le fichier suspect. Il cree une copie controlee, calcule les hash avant et apres copie, verifie l'integrite et garde un historique complet dans le manifest et l'audit log.

Le champ `rootkit_profile.category` doit afficher `kernel_module_rootkit_suspect`, ce qui montre que le module est specialise pour les rootkits Linux.
