# Simulateur rootkit benin pour le laboratoire

## Important

Ce dossier ne contient pas de vrai rootkit.

Le simulateur cree uniquement des **artefacts inoffensifs** qui ressemblent a des traces de rootkit Linux :

- faux module kernel `.ko` ;
- faux fichier `ld.so.preload` dans un dossier de lab ;
- faux service systemd ;
- faux cron ;
- faux fichier cache dans `dev/shm` ;
- faux chemin de binaire systeme remplace ;
- faux fichier `modules-load.d` ;
- faux fichier `modprobe.d` ;
- snapshot statique d'incoherence `/proc` ;
- snapshot statique d'incoherence reseau ;
- marqueur de log tampering.

Il ne fait jamais les actions suivantes :

- pas de chargement de module noyau ;
- pas de modification du vrai `/etc/ld.so.preload` ;
- pas de creation de vrai service systemd ;
- pas de modification de vrai cron ;
- pas de persistance ;
- pas de dissimulation de fichiers, processus ou ports ;
- pas d'exploitation ;
- pas d'execution de malware ;
- pas d'ouverture de connexion reseau ;
- pas de modification de logs reels.

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

Cette commande cree les artefacts benins puis les met automatiquement en quarantaine avec le statut `READY_FOR_ANALYSIS`.

Les artefacts de laboratoire sont crees dans :

```text
runtime/rootkit-defense/lab-victim/
```

Elle cree aussi un fichier :

```text
runtime/rootkit-defense/lab-victim/alerts.json
```

Elle cree aussi :

```text
runtime/rootkit-defense/lab-victim/simulation_manifest.json
```

Ce manifest de campagne resume les artefacts, leurs categories attendues et les indicateurs defensifs.

## Lancer simulation sans quarantaine

```powershell
$env:PYTHONPATH="src"
python -m evidence_quarantine --storage-root .\runtime\rootkit-defense simulate-rootkit --scenario full --no-quarantine
```

Cette variante sert uniquement a generer les fichiers et `alerts.json` sans les envoyer dans Evidence & Quarantine Manager.

## Scenarios disponibles

```text
full           -> tous les artefacts benins
kernel-module  -> faux fichier .ko
ld-preload     -> faux ld.so.preload dans le lab
systemd        -> faux service systemd
cron           -> faux cron
hidden-payload -> faux fichier cache dans dev/shm
binary-tamper  -> faux chemin usr/bin/ps dans le lab
modules-load   -> faux chargement kernel au boot
modprobe       -> faux override modprobe/insmod
proc-inconsistency -> snapshot statique de processus cache
network-stealth    -> snapshot statique de connexion cachee
log-tamper     -> marqueur statique anti-forensic/log tampering
```

Exemple :

```powershell
python -m evidence_quarantine --storage-root .\runtime\rootkit-defense simulate-rootkit --scenario kernel-module
```

Exemple professionnel complet :

```powershell
python -m evidence_quarantine --storage-root .\runtime\rootkit-defense simulate-rootkit --scenario full
```

Ce test couvre les surfaces de detection suivantes :

```text
kernel module
ld.so.preload
systemd persistence
cron persistence
hidden runtime payload
binary tampering
modules-load persistence
modprobe override
process hiding indicator
hidden network connection indicator
log tampering indicator
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

> Pour respecter le cadre ethique du projet, je n'utilise pas de vrai rootkit. J'utilise un simulateur defensif qui reproduit les indicateurs observables d'un rootkit Linux : kernel module, preload hook, persistance, fichiers caches, incoherences de processus, reseau cache et anti-forensic. Les artefacts restent statiques et benins dans un dossier de laboratoire, ce qui permet de tester la detection, la quarantaine, les hash, la chain of custody et le handoff sandbox sans compromettre la machine.
