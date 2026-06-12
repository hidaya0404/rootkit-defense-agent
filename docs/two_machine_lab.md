# Scenario machine attaquante / machine victime

## Principe

Tu peux presenter un scenario realiste avec deux machines, sans utiliser de vrai rootkit.

```text
Machine attaquante
  Prepare ou envoie des artefacts benins de simulation
        |
        v
Machine victime Linux de lab
  Agent de detection + Evidence & Quarantine Manager
        |
        v
Quarantaine + sandbox + analyse IOC + rapport
```

## Ce que fait la machine attaquante

La machine attaquante ne lance pas de rootkit. Elle sert seulement a deposer des artefacts benins dans un dossier de lab de la machine victime.

Exemples d'artefacts :

```text
rk_demo.ko
ld.so.preload
rk-update.service
cron/root
.rk_stage
usr/bin/ps
```

Ces fichiers sont des marqueurs textuels ou binaires inoffensifs. Ils ne font aucune action systeme dangereuse.

## Ce que fait la machine victime

La machine victime execute :

```powershell
python -m evidence_quarantine --storage-root .\runtime\rootkit-defense simulate-rootkit --scenario full
```

Dans une vraie integration avec le Membre 1, l'agent detecte les fichiers crees et appelle ton module.

Pour une demo simple, la simulation met maintenant automatiquement les artefacts en quarantaine et montre directement ton resultat.

## Variante plus realiste

1. Machine attaquante prepare un zip contenant les artefacts benins.
2. Machine victime extrait le zip dans un dossier de lab, par exemple `~/rootkit-lab-victim`.
3. L'agent du Membre 1 detecte les fichiers suspects.
4. Ton module recoit les alertes.
5. Ton module produit les dossiers de preuve.

## Regle importante

Ne jamais utiliser :

```text
sudo insmod
sudo modprobe
sudo systemctl enable
crontab
modification du vrai /etc/ld.so.preload
```

Ces commandes ne sont pas necessaires pour la soutenance et peuvent affecter la machine.

## Message clair pour l'encadrant

> Le scenario est realiste au niveau des traces et du workflow de reponse a incident, mais il ne compromet pas la machine. Nous simulons les artefacts rootkit afin de valider la chaine defensive complete dans un cadre academique controle.

