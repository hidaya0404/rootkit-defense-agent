from __future__ import annotations

import json
import mimetypes
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from evidence_quarantine.backend_client import build_quarantine_manifest
from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.quarantine_manager import QuarantineManager
from evidence_quarantine.storage import read_json


def default_web_dir() -> Path:
    repo_web = Path(__file__).resolve().parents[1] / "web"
    if repo_web.exists():
        return repo_web
    cwd_web = Path.cwd() / "web"
    if cwd_web.exists():
        return cwd_web
    return repo_web


def load_ui_records(config: QuarantineConfig) -> list[dict[str, object]]:
    records = QuarantineManager(config).list_evidence()
    enriched: list[dict[str, object]] = []
    for record in records:
        item = dict(record)
        metadata_path = item.get("metadata_path")
        metadata = read_json(Path(str(metadata_path)), default={}) if metadata_path else {}
        profile = metadata.get("rootkit_profile") if isinstance(metadata, dict) else None
        if isinstance(profile, dict):
            item.setdefault("rootkit_category", profile.get("category"))
            item.setdefault("suspected_techniques", profile.get("suspected_techniques", []))
        enriched.append(item)
    return enriched


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def read_json_lines(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    records: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def load_alerts() -> list[dict[str, object]]:
    root = repo_root()
    candidates = [
        root / "logs" / "pending_alerts.jsonl",
        Path.cwd() / "logs" / "pending_alerts.jsonl",
    ]
    for candidate in candidates:
        alerts = read_json_lines(candidate)
        if alerts:
            return alerts
    return []


def load_sandbox_results() -> list[dict[str, object]]:
    root = repo_root()
    results_file = root / "backend" / "data" / "sandbox_results.json"
    results = read_json(results_file, default=[])
    if isinstance(results, list) and results:
        return results

    collected: list[dict[str, object]] = []
    sandbox_dir = root / "sandbox" / "results"
    if sandbox_dir.exists():
        for result_file in sorted(sandbox_dir.glob("*/sandbox_result.json")):
            item = read_json(result_file, default={})
            if isinstance(item, dict):
                collected.append(item)
    return collected


def load_reports() -> list[dict[str, object]]:
    root = repo_root()
    reports_file = root / "backend" / "data" / "reports.json"
    reports = read_json(reports_file, default=[])
    if isinstance(reports, list):
        return reports
    return []


def create_handler(config: QuarantineConfig, web_dir: Path) -> type[BaseHTTPRequestHandler]:
    web_root = web_dir.resolve()

    class RootkitDefenseUIHandler(BaseHTTPRequestHandler):
        server_version = "RootkitDefenseUI/1.0"

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlparse(self.path)
            if parsed.path == "/api/health":
                self._json(
                    {
                        "status": "ok",
                        "service": "rootkit-defense-ui",
                        "modules": ["agent", "quarantine", "sandbox", "analyzer"],
                    }
                )
                return
            if parsed.path == "/api/alerts":
                self._json(load_alerts())
                return
            if parsed.path == "/api/quarantine":
                self._json(load_ui_records(config))
                return
            if parsed.path == "/api/sandbox/results":
                self._json({"count": len(load_sandbox_results()), "results": load_sandbox_results()})
                return
            if parsed.path == "/api/reports":
                self._json({"count": len(load_reports()), "reports": load_reports()})
                return
            if parsed.path.startswith("/api/quarantine/"):
                if self._quarantine_api(parsed.path, config):
                    return
                self._not_found()
                return
            self._static(parsed.path)

        def log_message(self, format: str, *args: object) -> None:
            return

        def _json(self, payload: object, status: int = 200) -> None:
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _static(self, requested_path: str) -> None:
            safe_path = unquote(requested_path).lstrip("/") or "index.html"
            candidate = (web_root / safe_path).resolve()
            try:
                candidate.relative_to(web_root)
            except ValueError:
                self._not_found()
                return
            if not candidate.exists() or candidate.is_dir():
                self._not_found()
                return

            content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
            body = candidate.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _quarantine_api(self, path: str, config: QuarantineConfig) -> bool:
            parts = [part for part in path.split("/") if part]
            if len(parts) != 4 or parts[0] != "api" or parts[1] != "quarantine":
                return False

            alert_id = unquote(parts[2])
            action = parts[3]
            manager = QuarantineManager(config)
            record = manager.get_evidence(alert_id)
            if record is None:
                self._json({"error": "alert_id not found", "alert_id": alert_id}, status=404)
                return True

            if action == "manifest":
                self._json(
                    build_quarantine_manifest(
                        dict(record),
                        download_url=f"/api/quarantine/{alert_id}/download",
                    )
                )
                return True

            if action == "handoff":
                if not record.get("ready_for_sandbox"):
                    self._json({"error": "evidence not ready for sandbox"}, status=409)
                    return True
                self._json(
                    {
                        "alert_id": alert_id,
                        "artifact_id": record.get("artifact_id"),
                        "quarantine_path": record.get("quarantine_path") or record.get("artifact_path"),
                        "filename": record.get("filename") or record.get("artifact_name"),
                        "sha256": record.get("sha256"),
                        "download_url": f"/api/quarantine/{alert_id}/download",
                        "handoff_status": "READY_FOR_SANDBOX",
                    }
                )
                return True

            if action == "download":
                artifact_path = record.get("artifact_path") or record.get("quarantine_path")
                if not artifact_path:
                    self._json({"error": "artifact path missing"}, status=404)
                    return True
                path_obj = Path(str(artifact_path))
                if not path_obj.exists() or not path_obj.is_file():
                    self._json({"error": "artifact not found"}, status=404)
                    return True
                body = path_obj.read_bytes()
                filename = record.get("filename") or record.get("artifact_name") or "artifact.bin"
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return True

            return False

        def _not_found(self) -> None:
            body = b"Not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return RootkitDefenseUIHandler


def run_ui_server(
    config: QuarantineConfig,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    open_browser: bool = True,
    web_dir: Path | None = None,
) -> None:
    static_dir = (web_dir or default_web_dir()).resolve()
    handler = create_handler(config, static_dir)
    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{server.server_port}/"
    print(f"Rootkit Defense Agent UI: {url}")
    print(f"Storage root: {config.storage_root}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping UI server.")
    finally:
        server.server_close()
