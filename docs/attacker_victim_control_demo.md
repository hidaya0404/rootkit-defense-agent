# Demo controlee avec une machine attaquante et deux victimes

## Limite importante

Ce scenario n'utilise pas de vrai rootkit. Il utilise des artefacts benins qui ressemblent a des traces rootkit Linux.

Je ne recommande pas et je ne fournis pas :

- de rootkit reel ;
- de technique de furtivite ;
- de bypass antivirus ;
- de persistance reelle ;
- de modification du vrai `/etc/ld.so.preload` ;
- de chargement de module noyau avec `insmod` ou `modprobe`.

La machine victime sans notre solution ne detecte rien simplement parce que notre detecteur n'y est pas installe. Ce n'est pas une evasion, c'est une machine temoin.

## Topologie

```text
Machine attaquante de lab
  Cree un paquet d'artefacts rootkit benins
        |
        | scp / partage dossier / copie manuelle
        v
Victime 1 avec notre solution
  Lit alerts.json avec lab-detect
  Met les artefacts en quarantaine
  Produit metadata, hashes, audit, manifest

Victime 2 sans notre solution
  Recoit les memes fichiers
  Ne lance pas notre detecteur
  Sert de comparaison temoin
```

## Etape 1 - Machine attaquante

Sur la machine attaquante, generer les artefacts benins :

```bash
cd evidence-quarantine-manager
export PYTHONPATH=src
python -m evidence_quarantine \
  --storage-root ./attacker-work \
  simulate-rootkit \
  --scenario full \
  --lab-root ./attack-payload/rootkit-lab-drop
```

Le dossier important est :

```text
attack-payload/rootkit-lab-drop/
```

Il contient :

```text
alerts.json
tmp/rk_demo.ko
etc/ld.so.preload
etc/systemd/system/rk-update.service
var/spool/cron/root
dev/shm/.rk_stage
usr/bin/ps
```

Ces fichiers sont des marqueurs benins.

## Etape 2 - Envoyer aux deux victimes

Option avec archive :

```bash
tar -czf rootkit-lab-drop.tar.gz -C ./attack-payload rootkit-lab-drop
scp rootkit-lab-drop.tar.gz user@victim1:~/
scp rootkit-lab-drop.tar.gz user@victim2:~/
```

Tu peux aussi utiliser un dossier partage VirtualBox/VMware ou une copie manuelle.

## Etape 3 - Victime 1 avec notre solution

Sur la victime 1 :

```bash
mkdir -p ~/rootkit-defense-demo
tar -xzf ~/rootkit-lab-drop.tar.gz -C ~/rootkit-defense-demo
cd evidence-quarantine-manager
export PYTHONPATH=src
python -m evidence_quarantine \
  --storage-root ~/rootkit-defense-storage \
  lab-detect \
  --alerts-file ~/rootkit-defense-demo/rootkit-lab-drop/alerts.json
```

Resultat attendu :

```text
processed_alerts = 6
status = READY_FOR_ANALYSIS
metadata.json genere
hashes.json genere
audit.log genere
manifest.json genere
```

Pour verifier :

```bash
find ~/rootkit-defense-storage/quarantine -name metadata.json -print
```

## Etape 4 - Victime 2 sans notre solution

Sur la victime 2 :

```bash
mkdir -p ~/rootkit-defense-demo
tar -xzf ~/rootkit-lab-drop.tar.gz -C ~/rootkit-defense-demo
```

Ne lance pas `lab-detect`. Ne lance pas notre agent.

Resultat attendu :

```text
Les fichiers sont presents.
Il n'y a pas de dossier quarantine.
Il n'y a pas de metadata.json, hashes.json, audit.log ou manifest.json.
```

Cette machine sert de controle : sans detecteur, rien ne traite automatiquement les artefacts.

## Ce que tu dis au jury

> Nous avons deux victimes qui recoivent les memes artefacts rootkit benins. Sur la victime equipee de notre solution, l'agent detecte les artefacts, les classe selon le profil rootkit et les transmet au module de quarantaine. Sur la victime sans notre solution, il n'y a aucune detection par notre outil, ce qui montre le role de l'agent. Nous ne faisons aucune evasion et nous n'utilisons aucun vrai rootkit.

## Si on te demande pourquoi ce n'est pas un vrai rootkit

> Le cahier des charges interdit l'execution de vrais rootkits dangereux. Pour respecter le cadre ethique, on simule les traces observables d'un rootkit : module kernel suspect, ld.so.preload, systemd, cron, fichier cache et binaire systeme suspect. Cela valide la chaine defensive sans compromettre les machines.

