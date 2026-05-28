# Texte de soutenance pour Membre 2

## Presentation courte

Ma partie est le module **Evidence & Quarantine Manager**. Son role est d'isoler les artefacts suspects detectes par l'agent, tout en preservant les preuves numeriques. Le module applique une approche inspiree de la reponse a incident : validation du chemin, collecte forensic des metadonnees, calcul des hash, copie non destructive, verification d'integrite, journalisation d'audit et chain of custody.

Comme le projet cible les rootkits Linux, le module ajoute aussi un profil rootkit de l'artefact : module kernel `.ko`, hook `ld.so.preload`, persistance systemd ou cron, librairie `.so`, payload cache ou executable depose dans un repertoire temporaire.

## Probleme traite

Lorsqu'un fichier suspect est detecte, il ne faut pas le supprimer directement. Une suppression peut detruire une preuve, masquer l'origine de l'incident ou rendre le systeme instable. Mon module permet donc de securiser l'artefact tout en conservant les informations necessaires pour l'analyse sandbox, la generation d'IOC et le rapport final.

## Ce que mon module produit

Pour chaque alerte, le module cree un dossier de preuve contenant :

- `artifact.bin` : copie controlee du fichier suspect ;
- `metadata.json` : informations forensic ;
- `hashes.json` : MD5, SHA1, SHA256 avant et apres copie ;
- `audit.log` : historique des actions ;
- `manifest.json` : description du package et chain of custody.

## Points professionnels a mentionner

- Le module est non destructif.
- Les liens symboliques sont refuses.
- Les chemins systeme critiques sont proteges par defaut.
- Les hash sont calcules avant et apres copie.
- Le statut final est `READY_FOR_ANALYSIS` uniquement si l'integrite est validee.
- Les donnees sont exposees au backend et a l'interface web.
- Les tests unitaires valident les cas normaux et les erreurs.
- Le profil rootkit oriente la suite de l'analyse : sandbox, YARA, readelf, strings ou verification par baseline propre.

## Reponse si le jury demande pourquoi artifact.bin

Le nom de sortie est standardise pour eviter les noms de fichiers dangereux ou trompeurs. Le nom original est conserve dans `metadata.json`, donc l'information forensic n'est pas perdue.

## Reponse si le jury demande pourquoi ne pas supprimer le fichier original

Dans une logique de reponse a incident, la priorite est de preserver la preuve. La suppression est une action de remediation qui doit etre decidee plus tard, apres analyse et validation.

## Reponse si le jury demande pourquoi hash avant et apres copie

Le double hash permet de verifier que la preuve copiee en quarantaine est identique a l'artefact original au moment de la collecte. Si les hash different, le module signale un probleme d'integrite.

## Conclusion

Cette partie transforme une detection brute en preuve exploitable. Elle fait le lien entre la detection, la sandbox, l'analyse IOC, le reporting et l'interface web.
