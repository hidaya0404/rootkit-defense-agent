# Module Sandbox - Membre 3

## 1. Présentation

Ce module correspond à la partie **Membre 3 : Sandbox et analyse comportementale** du projet **Rootkit Defense Agent**.

L’objectif de ce module est d’exécuter un artefact contrôlé dans une machine virtuelle isolée afin d’observer son comportement sans exposer la machine hôte.
La sandbox permet de :

* restaurer automatiquement une VM à partir d’un snapshot propre ;
* démarrer la VM en mode headless ;
* copier un artefact dans l’environnement isolé ;
* exécuter l’artefact avec un temps limité ;
* collecter les logs comportementaux ;
* récupérer les résultats sur la machine hôte ;
* générer un fichier JSON de synthèse ;
* restaurer la VM après l’analyse.

Ce module est strictement défensif et utilise uniquement des artefacts contrôlés pour la démonstration.

---

## 2. Rôle du module dans l’architecture globale

Le projet Rootkit Defense Agent suit une chaîne de traitement progressive :

```text
Détection par M1
      |
      v
Quarantaine par M2
      |
      v
Analyse comportementale par M3
      |
      v
Analyse approfondie, reporting et interface par M4
```

Le rôle du module sandbox est donc de recevoir un artefact suspect ou contrôlé, de l’exécuter dans une VM isolée, puis de produire des logs exploitables par le backend et l’interface web.

---

## 3. Technologies utilisées

```text
Système hôte        : Windows
Virtualisation      : Oracle VirtualBox
VM sandbox          : Ubuntu
Automatisation      : Python
Contrôle VM         : VBoxManage guestcontrol
Analyse dynamique   : Bash, strace, ps, ss, find
Format résultat     : JSON
```

---

## 4. Structure du dossier

```text
sandbox/
├── sandbox_orchestrator.py
├── sandbox_config.py
├── sandbox_config.example.py
├── guest_runner.sh
├── sample_artifacts/
│   └── benign_suspicious.sh
├── results/
│   └── .gitkeep
└── README_SANDBOX.md
```

Description des fichiers :

```text
sandbox_orchestrator.py
    Script principal côté hôte.
    Il restaure le snapshot, démarre la VM, copie l’artefact, lance l’analyse,
    récupère les résultats et restaure la VM.

sandbox_config.py
    Fichier de configuration local contenant les paramètres de la VM.
    Ce fichier ne doit pas être publié s’il contient un mot de passe réel.

sandbox_config.example.py
    Exemple de configuration sans données sensibles.

guest_runner.sh
    Script exécuté dans la VM Ubuntu.
    Il collecte les processus, connexions réseau, fichiers /tmp, stdout, stderr,
    strace et code de sortie.

sample_artifacts/benign_suspicious.sh
    Artefact contrôlé utilisé pour tester la sandbox.

results/
    Dossier contenant les résultats générés après chaque analyse.
```

---

## 5. Configuration de la VM sandbox

La VM utilisée pour ce module est :

```text
Nom de la VM       : RootkitSandbox
Système invité     : Ubuntu
Snapshot propre    : clean-state
Mode réseau        : Host-only
Utilisateur invité : asma
```

La VM est configurée en mode isolé afin d’éviter qu’un artefact analysé communique librement avec Internet ou avec d’autres machines.

Configuration recommandée dans VirtualBox :

```text
Network Adapter    : Host-only Adapter
Shared Clipboard   : Disabled
Drag and Drop      : Disabled
Shared Folders     : aucun dossier partagé
Snapshot           : clean-state
```

---

## 6. Dépendances installées dans la VM

Dans la VM Ubuntu, les outils suivants sont nécessaires :

```bash
sudo apt update
sudo apt install -y python3 python3-pip strace lsof procps iproute2 net-tools curl file
```

Ces outils permettent de collecter les informations nécessaires pendant l’analyse comportementale.

---

## 7. Configuration locale

Un fichier `sandbox_config.py` est utilisé localement pour configurer l’orchestrateur.

Exemple :

```python
VM_NAME = "RootkitSandbox"
SNAPSHOT_NAME = "clean-state"

VBOXMANAGE = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

GUEST_USER = "asma"
GUEST_PASSWORD = "CHANGE_ME"

REMOTE_WORKDIR = "/home/asma/sandbox_run"

BACKEND_URL = "https://accommodations-requiring-henry-workshops.trycloudflare.com"
SANDBOX_RESULT_ENDPOINT = "/api/sandbox/results"

LOCAL_RESULTS_DIR = "sandbox/results"
```

Remarque importante :
Le mot de passe réel ne doit pas être publié dans GitHub.
Le fichier `sandbox_config.py` doit rester local ou être remplacé par un fichier exemple sans mot de passe réel.

Tu peux aussi surcharger les identifiants au lancement avec des variables d'environnement :

```powershell
$env:RDA_GUEST_USER="asma"
$env:RDA_GUEST_PASSWORD="vrai_mot_de_passe"
python sandbox/sandbox_orchestrator.py --metadata sandbox/test_metadata.json
```

---

## 8. Fichiers ignorés par Git

Pour éviter de publier les résultats générés automatiquement et les informations sensibles, la configuration suivante peut être ajoutée dans `.gitignore` :

```gitignore
sandbox/sandbox_config.py
sandbox/results/*
!sandbox/results/.gitkeep
```

Le dossier `sandbox/results/` reste présent grâce au fichier `.gitkeep`, mais les analyses générées localement ne sont pas envoyées dans le dépôt.

---

## 9. Artefact de test utilisé

L’artefact contrôlé utilisé pour la démonstration est :

```text
sandbox/sample_artifacts/benign_suspicious.sh
```

Cet artefact est bénin. Il sert uniquement à simuler un comportement observable dans la sandbox :

* création d’un fichier dans `/tmp` ;
* création d’un dossier de test ;
* affichage d’informations système ;
* génération de sorties dans `stdout`.

Exemple de comportement attendu :

```text
/tmp/sandbox_created_file.txt
/tmp/sandbox_test_dir/modified.txt
```

---

## 10. Fonctionnement de l’orchestrateur

Le script principal est :

```text
sandbox/sandbox_orchestrator.py
```

Il exécute les étapes suivantes :

```text
1. Restaurer le snapshot clean-state
2. Démarrer la VM RootkitSandbox en mode headless
3. Attendre que le guest soit disponible
4. Créer le dossier de travail dans la VM
5. Copier l’artefact dans la VM
6. Copier le script guest_runner.sh dans la VM
7. Exécuter l’analyse comportementale
8. Récupérer les résultats vers sandbox/results/
9. Générer sandbox_result.json
10. Arrêter la VM
11. Restaurer à nouveau le snapshot clean-state
12. Envoyer le résultat vers le backend si disponible
```

L’orchestrateur utilise `VBoxManage guestcontrol` au lieu de SSH/SCP.
Ce choix permet de contrôler directement la VM via VirtualBox et évite les problèmes de connexion SSH.

---

## 11. Lancement de l’analyse

Depuis la racine du projet :

```powershell
python sandbox/sandbox_orchestrator.py
```

Résultat attendu dans le terminal :

```text
[+] Restauration du snapshot propre
[+] Demarrage de la VM sandbox
[+] Attente disponibilite du guest
[+] Preparation dossier sandbox dans la VM
[+] Copie de l'artefact vers la VM
[+] Copie du runner vers la VM
[+] Lancement analyse comportementale
[+] Recuperation des resultats
[+] Resultat JSON genere
[+] Arret de la VM sandbox
[+] Restauration du snapshot propre
```

Si le backend de M4 n’est pas encore lancé, le message suivant peut apparaître :

```text
Backend indisponible ou endpoint non pret
```

Ce message n’empêche pas la réussite de l’analyse locale. Il indique seulement que l’intégration avec le backend n’est pas encore disponible.

---

## 12. Résultats générés

Après l’exécution, un dossier est créé automatiquement dans :

```text
sandbox/results/
```

Exemple :

```text
sandbox/results/analysis_20260528_201847/
├── exit_code.txt
├── files_tmp_after.txt
├── files_tmp_before.txt
├── network_after.txt
├── network_before.txt
├── processes_after.txt
├── processes_before.txt
├── sandbox_result.json
├── stderr.log
├── stdout.log
├── strace.log
├── timestamp_end.txt
└── timestamp_start.txt
```

---

## 13. Description des logs collectés

```text
processes_before.txt
    Liste des processus avant l’exécution de l’artefact.

processes_after.txt
    Liste des processus après l’exécution de l’artefact.

network_before.txt
    État des connexions réseau avant l’exécution.

network_after.txt
    État des connexions réseau après l’exécution.

files_tmp_before.txt
    Liste des fichiers présents dans /tmp avant l’exécution.

files_tmp_after.txt
    Liste des fichiers présents dans /tmp après l’exécution.

stdout.log
    Sortie standard produite par l’artefact.

stderr.log
    Erreurs produites pendant l’exécution.
    Ce fichier peut être vide si aucune erreur n’est produite.

strace.log
    Trace des appels système observés pendant l’exécution.

exit_code.txt
    Code de sortie de l’artefact.
    La valeur 0 indique une exécution réussie.

timestamp_start.txt
    Date et heure de début de l’analyse.

timestamp_end.txt
    Date et heure de fin de l’analyse.

sandbox_result.json
    Résumé structuré de l’analyse au format JSON.
```

---

## 14. Exemple de résultat JSON

Exemple de fichier `sandbox_result.json` généré :

```json
{
    "analysis_id": "analysis_20260528_201847",
    "timestamp": "2026-05-28T19:22:07.781331+00:00",
    "artifact_name": "benign_suspicious.sh",
    "artifact_sha256": "ce91afe037f79a31b8a2662dcf7978b377357ecd08b31a31f93e6405f63b8e15",
    "sandbox_vm": "RootkitSandbox",
    "snapshot_used": "clean-state",
    "status": "DONE",
    "behavior_logs": {
        "processes_before": "processes_before.txt",
        "processes_after": "processes_after.txt",
        "network_before": "network_before.txt",
        "network_after": "network_after.txt",
        "files_tmp_before": "files_tmp_before.txt",
        "files_tmp_after": "files_tmp_after.txt",
        "strace": "strace.log",
        "stdout": "stdout.log",
        "stderr": "stderr.log",
        "exit_code": "exit_code.txt"
    },
    "local_result_path": "sandbox/results/analysis_20260528_201847"
}
```

---

## 15. Interprétation du test local

Le test local montre que :

```text
La VM est restaurée au snapshot clean-state.
La VM démarre automatiquement.
L’artefact contrôlé est copié dans la VM.
Le script guest_runner.sh est exécuté dans la VM.
Les logs comportementaux sont collectés.
Le fichier sandbox_result.json est généré.
La VM est arrêtée après l’analyse.
Le snapshot clean-state est restauré après l’analyse.
```

Dans le test réalisé :

```text
exit_code.txt contient 0
```

Cela signifie que l’artefact s’est exécuté correctement.

Le fichier :

```text
stderr.log
```

peut être vide, car l’artefact n’a pas généré d’erreur.

Le fichier :

```text
files_tmp_before.txt
```

peut aussi être vide si le dossier `/tmp` ne contenait aucun fichier avant l’analyse.

Le fichier :

```text
files_tmp_after.txt
```

permet de vérifier les fichiers créés ou modifiés après l’exécution.

---

## 16. Intégration avec le backend M4

À la fin de l’analyse, le module tente d’envoyer le résultat au backend :

```text
POST /api/sandbox/results
```

Exemple d’URL locale :

```text
https://accommodations-requiring-henry-workshops.trycloudflare.com/api/sandbox/results
```

Si le backend n’est pas encore lancé ou si l’endpoint n’est pas encore disponible, le résultat est tout de même conservé localement dans :

```text
sandbox/results/
```

Pour l’intégration finale, M4 doit fournir :

```text
BACKEND_URL
POST /api/sandbox/results
GET /api/sandbox/results
```

---

## 17. Points de sécurité

Le module respecte les principes suivants :

```text
L’artefact n’est jamais exécuté sur la machine hôte.
L’exécution se fait uniquement dans la VM sandbox.
La VM est restaurée avant chaque analyse.
La VM est restaurée après chaque analyse.
Les résultats sont collectés avant la restauration finale.
Le réseau de la VM est isolé.
Les partages avec l’hôte sont désactivés.
```

---

## 18. Captures recommandées pour la documentation

Pour documenter cette partie, les captures suivantes sont recommandées :

```text
Capture 1 : VM RootkitSandbox dans VirtualBox
Capture 2 : Snapshot clean-state
Capture 3 : Configuration réseau Host-only
Capture 4 : Arborescence du dossier sandbox/
Capture 5 : Exécution de python sandbox/sandbox_orchestrator.py
Capture 6 : Résultat terminal avec status DONE
Capture 7 : Dossier sandbox/results/analysis_xxx/
Capture 8 : Contenu de sandbox_result.json
Capture 9 : Fichier files_tmp_after.txt montrant les fichiers créés
Capture 10 : Fichier exit_code.txt contenant 0
```

Exemple d’insertion des captures dans le README principal :

```markdown
![VM RootkitSandbox](docs/images/sandbox_vm.png)

![Snapshot clean-state](docs/images/snapshot_clean_state.png)

![Résultat de l’analyse sandbox](docs/images/sandbox_execution.png)

![Dossier des résultats](docs/images/sandbox_results.png)
```

---

## 19. Limites actuelles

La version actuelle est un MVP académique. Elle permet de démontrer le fonctionnement de la sandbox, mais certaines améliorations restent possibles :

```text
Récupération automatique des artefacts depuis GET /api/quarantine
Envoi final des résultats vers le backend M4
Affichage des résultats dans la page Analyse dynamique
Analyse plus avancée des logs strace
Extraction automatique des comportements suspects
Génération d’un score comportemental
```

---

## 20. État d’avancement

```text
VM sandbox configurée                         : terminé
Snapshot clean-state                           : terminé
Restauration automatique avant analyse         : terminé
Copie de l’artefact dans la VM                 : terminé
Exécution contrôlée de l’artefact              : terminé
Collecte des processus                         : terminé
Collecte réseau                                : terminé
Collecte fichiers /tmp                         : terminé
Collecte stdout/stderr                         : terminé
Collecte strace                                : terminé
Génération sandbox_result.json                 : terminé
Restauration automatique après analyse         : terminé
Intégration backend M4                         : en attente
Récupération artefacts M2                      : en attente
Page analyse dynamique                         : à intégrer avec l’équipe
```

---

## 21. Conclusion

Le module sandbox du Membre 3 est fonctionnel en local.

Il permet d’automatiser l’analyse comportementale d’un artefact contrôlé dans une VM Ubuntu isolée.
La VM est restaurée à partir du snapshot `clean-state`, l’artefact est exécuté dans l’environnement invité, les logs comportementaux sont collectés, puis la VM est arrêtée et restaurée afin de garantir un état propre pour les analyses suivantes.

L’intégration finale dépend du backend M4, notamment pour l’envoi des résultats vers l’endpoint :

```text
POST /api/sandbox/results
```
