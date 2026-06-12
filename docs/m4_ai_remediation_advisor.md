# M4 - AI Remediation Advisor

## Objectif

Le module `RDA-Remediation-AI` ajoute une couche de recommandation intelligente a la partie M4.
Il transforme les resultats d'analyse statique, IOC, YARA, scoring et sandbox en plan de remediation defensive.

Le modele est local au projet :

- aucune API externe ;
- aucune donnee envoyee vers un service tiers ;
- aucune action destructive automatique ;
- validation humaine obligatoire avant remediation.

## Entrees utilisees

Le moteur utilise les champs disponibles dans l'artefact et son analyse :

- `risk_score` et `risk_level` ;
- `strings_sample` ;
- `iocs` ;
- `yara_matches` ;
- `elf_analysis` ;
- `metadata` ;
- `sandbox_result` si disponible.

## Playbooks disponibles

Le modele classe l'incident dans un playbook defensif :

- `kernel_module_rootkit_response` ;
- `ld_preload_userland_hook_response` ;
- `persistence_mechanism_response` ;
- `network_ioc_response` ;
- `anti_forensic_log_tamper_response` ;
- `generic_suspicious_artifact_response`.

## Sortie produite

Chaque recommandation AI contient :

- le playbook choisi ;
- un score de confiance ;
- les signaux qui ont motive le choix ;
- une decision de remediation ;
- les actions de containment ;
- les actions d'investigation ;
- les actions de remediation ;
- les actions de validation.

## Integration M4

Le module est integre dans :

- `analysis/static_analyzer.py` pour enrichir le resultat d'analyse ;
- `analysis/remediation.py` pour construire un plan de remediation AI ;
- `reporting/report_generator.py` pour afficher les recommandations dans les rapports HTML/PDF.

## Principe de securite

Le systeme propose uniquement des actions defensives.
Il ne supprime pas automatiquement les fichiers, ne decharge pas de module kernel et ne modifie pas la machine sans validation humaine.
