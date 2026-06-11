import requests
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared.config import CONFIG

def upload_artifact(alert_id, file_path, sha256):
    """
    Uploader un artefact suspect vers M4
    lié à une alerte via alert_id
    """
    if not os.path.isfile(file_path):
        print(f"[UPLOAD] ⚠️ Fichier introuvable : {file_path}")
        return False

    try:
        url = CONFIG["backend_url"] + "/api/artifacts/upload"

        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
            data = {
                'alert_id': alert_id,
                'sha256': sha256,
                'original_path': file_path
            }
            response = requests.post(url, files=files, data=data, timeout=10)

        if response.status_code == 200:
            print(f"[UPLOAD] ✅ Artefact uploadé : {file_path}")
            return True
        else:
            print(f"[UPLOAD] ⚠️ Erreur status : {response.status_code}")
            return False

    except Exception as e:
        print(f"[UPLOAD] ⚠️ Erreur : {e}")
        return False
