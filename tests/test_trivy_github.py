"""Client GitHub de la surveillance Trivy : API, ZIP borné, isolement du jeton.

Les serveurs HTTP sont locaux : l'accès réel (liste des runs/artefacts anonyme,
téléchargement exigeant un jeton) a été vérifié à l'audit, ces tests verrouillent
l'implémentation et les refus.
"""

from __future__ import annotations

import http.server
import io
import json
import sys
import threading
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "app") not in sys.path:
    sys.path.insert(0, str(ROOT / "app"))

import trivy_github  # noqa: E402


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - API de la stdlib
        server = self.server
        server.seen.append({"path": self.path, "headers": dict(self.headers.items())})
        route = server.routes.get(self.path.split("?")[0])
        if route is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        status, headers, body = route
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        return


class _Server:
    def __init__(self):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.routes = {}
        self.httpd.seen = []
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"

    @property
    def seen(self):
        return self.httpd.seen

    def route(self, path: str, status: int, body: bytes = b"", headers=None):
        self.httpd.routes[path] = (status, headers or {}, body)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture()
def server(monkeypatch):
    instance = _Server()
    monkeypatch.setattr(trivy_github, "API_ROOT", instance.base)
    monkeypatch.setattr(trivy_github, "API_NETLOC", instance.base.split("//", 1)[1])
    yield instance
    instance.close()


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _runs_payload(run_id: int = 4242, commit: str = "a" * 40) -> bytes:
    return json.dumps(
        {
            "workflow_runs": [
                {
                    "id": run_id,
                    "head_sha": commit,
                    "html_url": f"https://github.com/Tetrax/hub/actions/runs/{run_id}",
                    "run_started_at": "2026-09-17T05:23:11Z",
                    "created_at": "2026-09-17T05:23:00Z",
                }
            ]
        }
    ).encode()


def _artifacts_payload(artifact_id: int = 99, *, expired: bool = False, name: str = "trivy-report") -> bytes:
    return json.dumps(
        {
            "artifacts": [
                {
                    "id": artifact_id,
                    "name": name,
                    "expired": expired,
                    "size_in_bytes": 1234,
                }
            ]
        }
    ).encode()


def _routes(server, *, artifact_id: int = 99, zip_body: bytes | None = None, run_id: int = 4242):
    server.route(
        "/repos/Tetrax/hub/actions/workflows/ci.yml/runs",
        200,
        _runs_payload(run_id),
        {"Content-Type": "application/json"},
    )
    server.route(
        f"/repos/Tetrax/hub/actions/runs/{run_id}/artifacts",
        200,
        _artifacts_payload(artifact_id),
        {"Content-Type": "application/json"},
    )
    server.route(
        f"/repos/Tetrax/hub/actions/artifacts/{artifact_id}/zip",
        200,
        zip_body if zip_body is not None else _zip_bytes({"trivy.json": b"{}"}),
        {"Content-Type": "application/zip"},
    )


# --- API ----------------------------------------------------------------------


def test_latest_run_is_parsed(server):
    _routes(server)
    run = trivy_github.latest_successful_run("jeton-de-test")
    assert run.run_id == "4242"
    assert run.commit == "a" * 40
    assert run.started_at == "2026-09-17T05:23:11Z"
    assert run.run_url.endswith("/actions/runs/4242")


def test_the_token_is_sent_to_the_api_host(server):
    _routes(server)
    trivy_github.latest_successful_run("jeton-de-test")
    assert server.seen[0]["headers"].get("Authorization") == "Bearer jeton-de-test"


def test_missing_token_is_a_clear_refusal(server):
    server.route("/repos/Tetrax/hub/actions/workflows/ci.yml/runs", 401, b"{}")
    with pytest.raises(trivy_github.GitHubError) as error:
        trivy_github.latest_successful_run("")
    assert "401" in str(error.value)


@pytest.mark.parametrize(
    ("status", "needle"),
    [(403, "403"), (404, "404"), (429, "429"), (500, "500")],
)
def test_http_errors_are_named(server, status, needle):
    server.route("/repos/Tetrax/hub/actions/workflows/ci.yml/runs", status, b"{}")
    with pytest.raises(trivy_github.GitHubError) as error:
        trivy_github.latest_successful_run("jeton")
    assert needle in str(error.value)


def test_no_successful_run_is_refused(server):
    server.route(
        "/repos/Tetrax/hub/actions/workflows/ci.yml/runs",
        200,
        json.dumps({"workflow_runs": []}).encode(),
    )
    with pytest.raises(trivy_github.GitHubError) as error:
        trivy_github.latest_successful_run("jeton")
    assert "Aucun run" in str(error.value)


def test_artifact_absent_is_refused(server):
    _routes(server)
    server.route(
        "/repos/Tetrax/hub/actions/runs/4242/artifacts",
        200,
        json.dumps({"artifacts": [{"id": 1, "name": "autre", "expired": False}]}).encode(),
    )
    with pytest.raises(trivy_github.GitHubError) as error:
        trivy_github.find_artifact("4242", "jeton")
    assert "absent" in str(error.value)


def test_expired_artifact_is_refused(server):
    _routes(server)
    server.route(
        "/repos/Tetrax/hub/actions/runs/4242/artifacts",
        200,
        _artifacts_payload(expired=True),
    )
    with pytest.raises(trivy_github.GitHubError) as error:
        trivy_github.find_artifact("4242", "jeton")
    assert "expiré" in str(error.value)


def test_download_is_bounded(server, monkeypatch):
    monkeypatch.setattr(trivy_github, "MAX_ARTIFACT_BYTES", 64)
    _routes(server, zip_body=b"x" * 4096)
    with pytest.raises(trivy_github.GitHubError) as error:
        trivy_github.download_artifact(99, "jeton")
    assert "limite" in str(error.value)


def test_authorization_is_stripped_on_a_cross_host_redirect(server, monkeypatch):
    """L'URL signée est sur un autre hôte : le jeton ne doit pas y être renvoyé."""
    signed = _Server()
    try:
        signed.route("/signed/artifact", 200, _zip_bytes({"trivy.json": b"{}"}))
        server.route(
            "/repos/Tetrax/hub/actions/artifacts/99/zip",
            302,
            b"",
            {"Location": f"{signed.base}/signed/artifact"},
        )
        raw = trivy_github.download_artifact(99, "jeton-de-test")
        assert raw
        assert signed.seen, "la redirection n'a pas été suivie"
        assert "Authorization" not in signed.seen[0]["headers"]
        assert server.seen[0]["headers"].get("Authorization") == "Bearer jeton-de-test"
    finally:
        signed.close()


# --- ZIP ------------------------------------------------------------------------


def test_report_is_extracted_from_the_archive():
    raw = trivy_github.extract_report(_zip_bytes({"trivy.json": b'{"SchemaVersion": 2}'}))
    assert raw == b'{"SchemaVersion": 2}'


def test_a_renamed_single_json_is_accepted():
    raw = trivy_github.extract_report(_zip_bytes({"rapport.json": b"{}"}))
    assert raw == b"{}"


def test_trivy_json_wins_when_another_json_is_present():
    """`trivy.json` est le rapport attendu : il prime sur un autre JSON présent."""
    raw = trivy_github.extract_report(
        _zip_bytes({"autre.json": b'{"autre": 1}', "trivy.json": b'{"ok": 1}'})
    )
    assert raw == b'{"ok": 1}'


@pytest.mark.parametrize(
    "entries",
    [
        {"../evil.json": b"{}"},
        {"/absolu.json": b"{}"},
        {"dossier/rapport.json": b"{}"},
        {"trivy.json": b"{}", "un.txt": b"x", "deux.txt": b"y", "trois.txt": b"z", "quatre.txt": b"w"},
        {"rapport.txt": b"pas du json"},
    ],
)
def test_unsafe_archives_are_refused(entries):
    with pytest.raises(trivy_github.GitHubError):
        trivy_github.extract_report(_zip_bytes(entries))


def test_a_directory_entry_is_refused():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("sous-dossier/", b"")
        archive.writestr("trivy.json", b"{}")
    with pytest.raises(trivy_github.GitHubError):
        trivy_github.extract_report(buffer.getvalue())


def test_a_broken_zip_is_refused():
    with pytest.raises(trivy_github.GitHubError):
        trivy_github.extract_report(b"ceci n'est pas un zip")


def test_an_oversized_report_is_refused(monkeypatch):
    monkeypatch.setattr(trivy_github, "MAX_ARTIFACT_BYTES", 128)
    payload = _zip_bytes({"trivy.json": b"x" * 4096})
    with pytest.raises(trivy_github.GitHubError):
        trivy_github.extract_report(payload)
