"""Emails de changement : composition (DA SNS, échappement, liens validés) et envoi SMTP.

Le transport est exercé contre un serveur SMTP factice local : dialogue réel
(smtplib), succès et pannes — sans jamais contacter un vrai relais.
"""

from __future__ import annotations

import base64
import email as email_module
import email.policy  # sous-module requis par message_from_string(policy=...)
import socket
import threading

import pytest

from app import db, trivy_email, trivy_monitor
from app.trivy import Scan


class FakeSmtp(threading.Thread):
    """Serveur SMTP minimal : 220, EHLO, MAIL, RCPT, DATA, QUIT (+ AUTH facultatif)."""

    def __init__(self, *, refuse_recipient: bool = False, auth_ok: bool = True, advertise_auth: bool = False):
        super().__init__(daemon=True)
        self.refuse_recipient = refuse_recipient
        self.auth_ok = auth_ok
        self.advertise_auth = advertise_auth
        self.messages: list[str] = []
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(1)
        # Réveil périodique : `close()` doit réellement libérer le port, sans rester
        # bloqué dans accept() (un accept bloquant retient le socket ouvert).
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                client, _addr = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with client:
                self._session(client)

    def _session(self, client):
        stream = client.makefile("rb")
        client.sendall(b"220 fake.local ESMTP\r\n")
        data_lines: list[str] = []
        in_data = False
        auth_pending = 0
        while True:
            line = stream.readline()
            if not line:
                return
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if in_data:
                if text == ".":
                    in_data = False
                    self.messages.append("\n".join(data_lines))
                    data_lines = []
                    client.sendall(b"250 OK queued\r\n")
                else:
                    data_lines.append(text)
                continue
            upper = text.upper()
            if auth_pending:
                auth_pending -= 1
                if auth_pending:
                    client.sendall(b"334 UGFzc3dvcmQ6\r\n")
                else:
                    client.sendall(b"235 ok\r\n" if self.auth_ok else b"535 auth failed\r\n")
            elif upper.startswith("EHLO"):
                if self.advertise_auth:
                    client.sendall(b"250-fake.local\r\n250-AUTH PLAIN LOGIN\r\n250 HELP\r\n")
                else:
                    client.sendall(b"250-fake.local\r\n250 HELP\r\n")
            elif upper.startswith("HELO") or upper.startswith("MAIL") or upper.startswith("RSET"):
                client.sendall(b"250 OK\r\n")
            elif upper.startswith("AUTH"):
                if not self.auth_ok:
                    client.sendall(b"535 auth failed\r\n")
                elif upper.startswith("AUTH PLAIN") and len(text.split()) > 2:
                    client.sendall(b"235 ok\r\n")
                else:
                    auth_pending = 2
                    client.sendall(b"334 VXNlcm5hbWU6\r\n")
            elif upper.startswith("RCPT"):
                if self.refuse_recipient:
                    client.sendall(b"550 recipient refused\r\n")
                else:
                    client.sendall(b"250 OK\r\n")
            elif upper.startswith("DATA"):
                in_data = True
                client.sendall(b"354 ready\r\n")
            elif upper.startswith("QUIT"):
                client.sendall(b"221 Bye\r\n")
                return
            else:
                client.sendall(b"250 OK\r\n")

    def close(self):
        self._stop = True
        try:
            self.socket.close()
        except OSError:
            pass


@pytest.fixture()
def smtp_server():
    servers: list[FakeSmtp] = []

    def _make(**kwargs) -> FakeSmtp:
        server = FakeSmtp(**kwargs)
        server.start()
        servers.append(server)
        return server

    yield _make
    for server in servers:
        server.close()


def configure(app, server: FakeSmtp | None, *, notifications: bool = True, username: str = "",
              allow_errors: bool = False, **overrides):
    app.config["SMTP_PASSWORD"] = "mot-de-passe-smtp" if username else ""
    connection = db.connect(app.config["DB_PATH"])
    form = {
        "sync_enabled": "1",
        "notifications_enabled": "1" if notifications else "0",
        "notify_new": "1", "notify_resolved": "1", "notify_severity": "1",
        "severity_critical": "1", "severity_high": "1",
        "recipients": "equipe@valdev.me",
        "smtp_host": "127.0.0.1" if server else "",
        "smtp_port": str(server.port) if server else "587",
        "smtp_security": "none",
        "smtp_username": username,
        "smtp_from": "sns-hub@valdev.me",
        "smtp_timeout": "10",
    }
    form.update(overrides)
    values, errors = trivy_monitor.validate_settings(
        form, github_token_present=True, smtp_password_present=bool(username)
    )
    if not allow_errors:
        assert not errors, errors
    trivy_monitor.save_settings(connection, values)
    connection.close()


EVENTS = [
    {
        "kind": "new",
        "severity": "critical",
        "summary": "Apparition — CVE-2026-0001 (perl-base, CRITICAL)",
        "detail": {
            "cve": "CVE-2026-0001",
            "package": "perl-base",
            "installed_version": "5.40.1-6",
            "fixed_version": "5.40.1-6+deb13u1",
            "advisory_url": "https://avd.aquasec.com/nvd/cve-2026-0001",
        },
    },
    {
        "kind": "resolved",
        "severity": "high",
        "summary": "Vulnérabilité non détectée dans la nouvelle image — CVE-2026-0002 (gzip, HIGH)",
        "detail": {
            "cve": "CVE-2026-0002",
            "package": "gzip",
            "installed_version": "1.13-1",
            "fixed_version": "",
            "advisory_url": "",
        },
    },
    {
        "kind": "severity_up",
        "severity": "critical",
        "summary": "Aggravation — CVE-2026-0003 (libsqlite3-0) : HIGH → CRITICAL",
        "detail": {
            "cve": "CVE-2026-0003",
            "package": "libsqlite3-0",
            "installed_version": "3.46.1-7",
            "fixed_version": "3.46.1-7+deb13u1",
            "previous_severity": "high",
            "advisory_url": "",
        },
    },
]

SCAN = Scan(image="hub:ci-scan", commit="86dc08064112e9a2cc809b82793bf230dbe948eb",
            scanned_at="2026-09-18T05:24:00Z", findings=())


# --- Composition --------------------------------------------------------------------


def test_subject_uses_singular_and_plural():
    assert trivy_email.compose_subject(EVENTS[:1]) == "[SNS Hub] Sécurité de l'image — 1 changement détecté"
    assert trivy_email.compose_subject(EVENTS) == "[SNS Hub] Sécurité de l'image — 3 changements détectés"


def test_bodies_carry_the_summary_the_rows_and_the_provenance():
    text, html = trivy_email.compose_bodies(EVENTS, SCAN, base_url="https://hub.valdev.me")
    assert "Nouveaux : 1 CRITICAL" in text
    assert "Non détectées dans la nouvelle image : 1" in text
    assert "Changements de sévérité : 1" in text
    assert "HIGH → CRITICAL" in text
    assert "commit 86dc08064112" not in text and "Commit : 86dc08064112" in text
    assert "2026-09-18T05:24:00Z" in text
    assert "https://hub.valdev.me/admin/security" in text
    assert "perl-base" in html and "Voir dans SNS Hub" in html
    assert "SNS" in html and "#F4A8C9" in html  # direction artistique conservée


def test_the_run_link_is_included_when_available():
    text, html = trivy_email.compose_bodies(
        EVENTS, SCAN, base_url="", run_url="https://github.com/Tetrax/hub/actions/runs/123"
    )
    assert "Run GitHub : https://github.com/Tetrax/hub/actions/runs/123" in text
    assert "voir le run" in html


def test_hostile_values_are_escaped_and_invalid_links_never_rendered():
    events = [
        {
            "kind": "new",
            "severity": "high",
            "summary": "x",
            "detail": {
                "cve": 'CVE-2026-0001"><script>alert(1)</script>',
                "package": "<img src=x onerror=alert(1)>",
                "installed_version": "1.0",
                "fixed_version": "1.1",
                "advisory_url": "javascript:alert(1)",
            },
        }
    ]
    text, html = trivy_email.compose_bodies(events, SCAN, base_url="")
    assert "<script>" not in html
    assert "<img" not in html
    assert "javascript:" not in html
    assert "&lt;script&gt;" in html


def test_an_advisory_url_is_rendered_only_when_https():
    events = [dict(EVENTS[0])]
    events[0]["detail"] = dict(EVENTS[0]["detail"])
    _text, html = trivy_email.compose_bodies(events, SCAN, base_url="")
    assert 'href="https://avd.aquasec.com/nvd/cve-2026-0001"' in html


def test_the_backslash_summary_has_no_sections_when_empty():
    text, _html = trivy_email.compose_bodies([], SCAN, base_url="")
    assert "Résumé :" in text
    assert "Nouveaux" not in text


# --- Transport SMTP -----------------------------------------------------------------


def test_a_successful_send_goes_through_the_real_smtp_dialogue(app, smtp_server):
    server = smtp_server()
    configure(app, server)
    ok, detail = trivy_email.send_delta_email(app, EVENTS, SCAN)
    assert ok, detail
    assert server.messages, "le serveur n'a reçu aucun message"
    parsed = email_module.message_from_string(
        server.messages[0], policy=email_module.policy.default
    )
    assert parsed["Subject"] == "[SNS Hub] Sécurité de l'image — 3 changements détectés"
    assert parsed["From"] == "sns-hub@valdev.me"
    assert parsed["To"] == "equipe@valdev.me"
    assert "text/html" in server.messages[0]


def test_a_refused_recipient_is_a_clean_error(app, smtp_server):
    server = smtp_server(refuse_recipient=True)
    configure(app, server)
    ok, detail = trivy_email.send_delta_email(app, EVENTS, SCAN)
    assert not ok
    assert detail == "Destinataire refusé par le serveur SMTP."


def test_an_authentication_failure_is_a_clean_error(app, smtp_server):
    server = smtp_server(auth_ok=False, advertise_auth=True)
    configure(app, server, username="hub")
    ok, detail = trivy_email.send_delta_email(app, EVENTS, SCAN)
    assert not ok
    assert detail == "Authentification SMTP refusée."


def test_an_unreachable_server_is_a_clean_error(app, smtp_server):
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    configure(app, None, smtp_host="127.0.0.1", smtp_port=str(port))
    ok, detail = trivy_email.send_delta_email(app, EVENTS, SCAN)
    assert not ok
    assert detail.startswith("Échec SMTP (connexion)")


def test_an_incomplete_configuration_refuses_before_any_connection(app):
    configure(app, None, allow_errors=True)
    ok, detail = trivy_email.send_delta_email(app, EVENTS, SCAN)
    assert not ok and "Configuration SMTP incomplète" in detail


def test_notifications_disabled_refuses_cleanly(app, smtp_server):
    server = smtp_server()
    configure(app, server, notifications=False)
    ok, detail = trivy_email.send_delta_email(app, EVENTS, SCAN)
    assert not ok and "Notifications désactivées" in detail
    assert server.messages == []


def test_the_test_email_uses_the_saved_configuration(app, smtp_server):
    server = smtp_server()
    configure(app, server)
    ok, detail = trivy_email.send_test_email(app)
    assert ok, detail
    parsed = email_module.message_from_string(
        server.messages[0], policy=email_module.policy.default
    )
    assert parsed["Subject"].startswith("[SNS Hub] Test")
    assert "CVE-0000-0000" in server.messages[0]


def test_the_test_email_refuses_an_incomplete_configuration(app):
    configure(app, None, allow_errors=True)
    ok, detail = trivy_email.send_test_email(app)
    assert not ok and "incomplète" in detail


def test_no_secret_ever_appears_in_the_rendered_email(app, smtp_server):
    server = smtp_server()
    configure(app, server, username="hub")
    app.config["SMTP_PASSWORD"] = "secret-smtp-a-ne-jamais-rendre"
    trivy_email.send_test_email(app)
    for message in server.messages:
        assert "secret-smtp-a-ne-jamais-rendre" not in message
