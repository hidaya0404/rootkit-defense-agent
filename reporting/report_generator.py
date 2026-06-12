from datetime import datetime
import uuid
import os
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def build_executive_summary(analysis):
    risk_level = analysis.get("risk_level", "UNKNOWN")
    risk_score = analysis.get("risk_score", 0)

    return (
        f"L’artefact analysé présente un niveau de risque {risk_level} "
        f"avec un score de {risk_score}/100. "
        "L’analyse statique a permis d’extraire des hash, des chaînes, des IOC, "
        "des résultats YARA et des recommandations de remédiation contrôlée."
    )


def generate_html_report(artifact, analysis):
    report_id = str(uuid.uuid4())
    html_path = f"reports/generated/report_{report_id}.html"
    pdf_path = f"reports/generated/report_{report_id}.pdf"

    os.makedirs("reports/generated", exist_ok=True)

    executive_summary = build_executive_summary(analysis)

    html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport Rootkit Defense Agent</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f4f4f4;
        }}
        .container {{
            background: white;
            padding: 25px;
            border-radius: 10px;
        }}
        h1, h2 {{
            color: #222;
        }}
        pre {{
            background: #eeeeee;
            padding: 10px;
            border-radius: 6px;
            overflow-x: auto;
        }}
        .risk {{
            font-weight: bold;
            font-size: 20px;
            color: red;
        }}
    </style>
</head>
<body>
<div class="container">
    <h1>Rapport d’analyse — Rootkit Defense Agent</h1>

    <h2>1. Résumé exécutif</h2>
    <p>{executive_summary}</p>

    <h2>2. Informations artefact</h2>
    <p><strong>Date :</strong> {datetime.utcnow().isoformat()}Z</p>
    <p><strong>Artifact ID :</strong> {artifact.get("artifact_id")}</p>
    <p><strong>Alert ID :</strong> {artifact.get("alert_id")}</p>
    <p><strong>Nom original :</strong> {artifact.get("original_filename")}</p>
    <p><strong>Chemin stocké :</strong> {artifact.get("stored_path")}</p>

    <h2>3. Métadonnées</h2>
    <pre>{analysis.get("metadata")}</pre>

    <h2>4. Hash</h2>
    <pre>{analysis.get("hashes")}</pre>

    <h2>5. Type de fichier</h2>
    <pre>{analysis.get("file_type")}</pre>

    <h2>6. Analyse ELF</h2>
    <pre>{analysis.get("elf_analysis")}</pre>

    <h2>7. IOC extraits</h2>
    <pre>{analysis.get("iocs")}</pre>

    <h2>8. Résultats YARA</h2>
    <pre>{analysis.get("yara_matches")}</pre>

    <h2>9. Score de risque</h2>
    <p class="risk">{analysis.get("risk_score")} / 100 — {analysis.get("risk_level")}</p>
    <pre>{analysis.get("risk_reasons")}</pre>

    <h2>10. Recommandations de remédiation</h2>
    <ul>
"""

    for rec in analysis.get("recommendations", []):
        html += f"<li>{rec}</li>"

    html += """
    </ul>

    <h2>11. Timeline incident</h2>
    <pre>
"""

    html += str(analysis.get("timeline", []))

    html += """
    </pre>

    <h2>12. Strings extraites</h2>
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

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    generate_pdf_report(pdf_path, artifact, analysis, executive_summary)

    return {
        "html_report": html_path,
        "pdf_report": pdf_path
    }


def generate_pdf_report(pdf_path, artifact, analysis, executive_summary):
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4

    y = height - 50

    def write_line(text, step=18):
        nonlocal y
        if y < 60:
            c.showPage()
            y = height - 50
        c.drawString(50, y, str(text)[:110])
        y -= step

    write_line("Rootkit Defense Agent - Rapport d'analyse", 25)
    write_line("Résumé exécutif :", 20)
    write_line(executive_summary, 35)

    write_line(f"Artifact ID : {artifact.get('artifact_id')}")
    write_line(f"Alert ID : {artifact.get('alert_id')}")
    write_line(f"Risk score : {analysis.get('risk_score')}/100")
    write_line(f"Risk level : {analysis.get('risk_level')}")

    write_line("Hash :", 20)
    for k, v in analysis.get("hashes", {}).items():
        write_line(f"{k}: {v}")

    write_line("IOC :", 20)
    write_line(analysis.get("iocs"))

    write_line("YARA :", 20)
    write_line(analysis.get("yara_matches"))

    write_line("Recommandations :", 20)
    for rec in analysis.get("recommendations", []):
        write_line(f"- {rec}")

    c.save()
