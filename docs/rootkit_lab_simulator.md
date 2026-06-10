# Simulateur rootkit benin pour le laboratoire

## Important

Ce dossier ne contient pas de vrai rootkit.

Le simulateur cree uniquement des **artefacts inoffensifs** qui ressemblent a des traces de rootkit Linux :

- faux module kernel `.ko` ;
- faux fichier `ld.so.preload` dans un dossier de lab ;
- faux service systemd ;
- faux cron ;
- faux fichier cache dans `dev/shm` ;
- faux chemin de binaire systeme remplace.

Il ne fait jamais les actions suivantes :

- pas de chargement de module noyau ;
- pas de modification du vrai `/etc/ld.so.preload` ;
- pas de creation de vrai service systemd ;
- pas de modification de vrai cron ;
- pas de persistance ;
- pas de dissimulation de fichiers, processus ou ports ;
- pas d'exploitation ;
- pas d'execution de malware.

Tout est ecrit dans un dossier de laboratoire, par exemple :

```text
runtime/rootkit-defense/lab-victim/
```

## Pourquoi c'est utile pour le projet

Le sujet du PFS cible les rootkits. Pour tester ton module sans danger, on simule les **artefacts observables** qu'un rootkit pourrait laisser.

Ton module peut donc montrer au jury :

```text
alerte rootkit
→ artefact suspect
→ classification rootkit
→ quarantaine
→ hash
→ metadata
→ audit log
→ manifest
→ ready for sandbox
```

## Lancer une simulation complete

Depuis le dossier du projet :

```powershell
$env:PYTHONPATH="src"
python -m evidence_quarantine --storage-root .\runtime\rootkit-defense simulate-rootkit --scenario full
```

Cette commande cree les artefacts benins dans :

```text
runtime/rootkit-defense/lab-victim/
```

Elle cree aussi un fichier :

```text
runtime/rootkit-defense/lab-victim/alerts.json
```

## Lancer simulation + quarantaine directement

```powershell
$env:PYTHONPATH="src"
python -m evidence_quarantine --storage-root .\runtime\rootkit-defense simulate-rootkit --scenario full --quarantine
```

Cette commande cree les artefacts puis les envoie directement dans ton module Evidence & Quarantine Manager.

## Scenarios disponibles

```text
full           -> tous les artefacts benins
kernel-module  -> faux fichier .ko
ld-preload     -> faux ld.so.preload dans le lab
systemd        -> faux service systemd
cron           -> faux cron
hidden-payload -> faux fichier cache dans dev/shm
binary-tamper  -> faux chemin usr/bin/ps dans le lab
```

Exemple :

```powershell
python -m evidence_quarantine --storage-root .\runtime\rootkit-defense simulate-rootkit --scenario kernel-module --quarantine
```

## Ce que tu montres au jury

Dans le dossier de quarantaine, ouvre `metadata.json`.

Tu dois voir un profil rootkit comme :

```json
{
  "category": "kernel_module_rootkit_suspect",
  "suspected_techniques": [
    "kernel_module_loading",
    "kernel_space_hiding"
  ],
  "mitre_attack_mapping": [
    "T1014 Rootkit",
    "T1547.006 Kernel Modules and Extensions"
  ]
}
```

## Phrase de soutenance

> Pour respecter le cadre ethique du projet, je n'utilise pas de vrai rootkit. J'utilise un simulateur defensif qui cree des artefacts benins ressemblant aux traces d'un rootkit Linux. Cela permet de tester la detection, la quarantaine, les hash, la chain of custody et le handoff sandbox sans compromettre la machine.

