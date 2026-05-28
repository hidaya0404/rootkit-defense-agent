from datetime import datetime
import uuid


def generate_html_report(artifact, analysis):
    report_id = str(uuid.uuid4())
    report_path = f"reports/generated/report_{report_id}.html"

    html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport d'analyse - Rootkit Defense Agent</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f7f7f7;
        }}

        .container {{
            background: white;
            padding: 25px;
            border-radius: 10px;
        }}

        h1, h2 {{
            color: #222;
        }}

        .risk {{
            font-size: 20px;
            font-weight: bold;
            color: red;
        }}

        pre {{
            background: #eee;
            padding: 10px;
            border-radius: 6px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
<div class="container">
    <h1>Rapport d'analyse statique</h1>

    <h2>Informations générales</h2>
    <p><strong>Date :</strong> {datetime.utcnow().isoformat()}Z</p>
    <p><strong>Artifact ID :</strong> {artifact.get("artifact_id")}</p>
    <p><strong>Alert ID :</strong> {artifact.get("alert_id")}</p>
    <p><strong>Nom original :</strong> {artifact.get("original_filename")}</p>
    <p><strong>Chemin stocké :</strong> {artifact.get("stored_path")}</p>

    <h2>Type et taille</h2>
    <p><strong>Type :</strong> {analysis.get("file_type")}</p>
    <p><strong>Taille :</strong> {analysis.get("size_bytes")} octets</p>

    <h2>Hash</h2>
    <pre>{analysis.get("hashes")}</pre>

    <h2>IOC extraits</h2>
    <pre>{analysis.get("iocs")}</pre>

    <h2>Résultats YARA</h2>
    <pre>{analysis.get("yara_matches")}</pre>

    <h2>Score de risque</h2>
    <p class="risk">{analysis.get("risk_score")} / 100 - {analysis.get("risk_level")}</p>

    <h2>Recommandations de remédiation</h2>
    <ul>
"""

    for rec in analysis.get("recommendations", []):
        html += f"<li>{rec}</li>"

    html += """
    </ul>

    <h2>Extrait des chaînes détectées</h2>
    <pre>
"""

    for s in analysis.get("strings_sample", []):
        html += s + "\n"

    html += """
    </pre>
</div>
</body>
</html>
"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    return report_path
