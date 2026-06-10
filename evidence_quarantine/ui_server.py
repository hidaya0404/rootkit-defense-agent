from __future__ import annotations

import json
import mimetypes
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

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


def create_handler(config: QuarantineConfig, web_dir: Path) -> type[BaseHTTPRequestHandler]:
    web_root = web_dir.resolve()

    class RootkitDefenseUIHandler(BaseHTTPRequestHandler):
        server_version = "RootkitDefenseUI/1.0"

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlparse(self.path)
            if parsed.path == "/api/health":
                self._json({"status": "ok", "service": "rootkit-defense-ui"})
                return
            if parsed.path == "/api/quarantine":
                self._json(load_ui_records(config))
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
