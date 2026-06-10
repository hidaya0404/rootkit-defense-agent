# Politique de securite

## Principes

Le module est strictement defensif. Il ne contient aucun rootkit, aucun exploit et aucune execution d'artefact suspect.

Il est specialise pour les **artefacts lies aux rootkits Linux** : modules kernel, fichiers de persistance, hooks userland, librairies partagees suspectes et payloads caches.

## Decisions de securite

### Pas de suppression automatique

Le fichier original n'est jamais supprime automatiquement. Une suppression directe ferait perdre une preuve et pourrait casser le systeme.

### Rejet des liens symboliques

Les liens symboliques sont refuses afin d'eviter qu'un chemin apparemment simple pointe vers un fichier critique ou change de cible pendant l'analyse.

### Refus des dossiers

La premiere version traite un artefact fichier par alerte. Les dossiers compresses ou ensembles de fichiers peuvent etre ajoutes comme evolution.

### Chemins systeme critiques

Par defaut, les chemins comme `/bin`, `/boot`, `/lib`, `/proc`, `/sys` et `/dev` sont refuses. Ils peuvent etre autorises uniquement dans un laboratoire controle avec `allow_system_paths=true`.

### Verification d'integrite

Le module calcule les hash avant et apres copie. Si le hash change, le statut devient `INTEGRITY_FAILED`.

### Permissions de quarantaine

Sous Linux, les dossiers sont crees en `0700` et les fichiers de preuve en `0600`. L'artefact copie est rendu en lecture seule `0400`.

## Limites

- Le module ne detecte pas les rootkits lui-meme.
- Le module n'execute pas l'artefact.
- Le module ne remplace pas une analyse forensic complete.
- La confiance dans les metadonnees depend de l'etat du systeme hote au moment de la collecte.

## Bonnes pratiques de demonstration

- Utiliser uniquement `examples/suspicious_demo.sh` ou un fichier benin.
- Utiliser le simulateur `simulate-rootkit` pour produire des traces rootkit sans danger.
- Executer la demo dans une VM Linux.
- Ne jamais utiliser de malware reel.
- Conserver les dossiers de preuve pour les captures d'ecran et le rapport.

## Commandes a ne pas utiliser

Les commandes suivantes ne sont pas necessaires pour ce projet et peuvent affecter une machine Linux :

```text
insmod
modprobe
systemctl enable
crontab
modification du vrai /etc/ld.so.preload
```

Le simulateur cree uniquement des fichiers dans le dossier de lab configure.
