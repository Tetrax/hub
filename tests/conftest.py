"""Fixtures partagées : application Flask isolée, certificats de test, helper local.

Les certificats de test sont générés avec `cryptography` (contrôle complet des dates
et des chaînes) ; le code de production les valide avec OpenSSL, comme en réel.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import struct
import sys
import threading
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for _path in (ROOT, ROOT / "app", ROOT / "helper"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from app import create_app  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "motdepasse-de-test-123"


# --- Génération de certificats ------------------------------------------------


def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def private_key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def make_certificate(
    *,
    cn: str = "hub.valdev.me",
    key=None,
    issuer_cert=None,
    issuer_key=None,
    sans=("hub.valdev.me",),
    days_before: float = -1,
    days_after: float = 365,
    is_ca: bool = False,
):
    """Retourne (cert_pem, key_obj). issuer_cert None => auto-signé."""
    key = key or make_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = issuer_cert.subject if issuer_cert is not None else subject
    signing_key = issuer_key if issuer_key is not None else key
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=days_before))
        .not_valid_after(now + timedelta(days=days_after))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in sans]),
            critical=False,
        )
    certificate = builder.sign(signing_key, hashes.SHA256())
    return certificate.public_bytes(serialization.Encoding.PEM), key


def leaf_certificate(cn: str = "hub.valdev.me", **kwargs):
    """(cert_pem, key_pem) auto-signé prêt à l'emploi."""
    cert_pem, key = make_certificate(cn=cn, **kwargs)
    return cert_pem, private_key_pem(key)


def chain_certificates():
    """Retourne (leaf_pem, leaf_key_pem, intermediate_pem, root_pem)."""
    root_pem, root_key = make_certificate(cn="Test Root CA", sans=None, is_ca=True)
    root_cert = x509.load_pem_x509_certificate(root_pem)
    intermediate_pem, intermediate_key = make_certificate(
        cn="Test Intermediate CA",
        sans=None,
        is_ca=True,
        issuer_cert=root_cert,
        issuer_key=root_key,
    )
    intermediate_cert = x509.load_pem_x509_certificate(intermediate_pem)
    leaf_pem, leaf_key = make_certificate(
        cn="hub.valdev.me",
        issuer_cert=intermediate_cert,
        issuer_key=intermediate_key,
    )
    return leaf_pem, private_key_pem(leaf_key), intermediate_pem, root_pem


# --- Images de test -----------------------------------------------------------


def make_png(width: int = 4, height: int = 3, color=(244, 168, 201)) -> bytes:
    raw = b"".join(b"\x00" + bytes(color) * width for _ in range(height))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


PNG_BYTES = make_png()
JPEG_LIKE = b"\xff\xd8\xff\xe0" + b"\x00" * 32
WEBP_LIKE = b"RIFF" + struct.pack("<I", 32) + b"WEBP" + b"VP8 " + b"\x00" * 20


# --- Application --------------------------------------------------------------


def _config(tmp_path: Path) -> dict:
    return {
        "DATA_DIR": tmp_path,
        "DB_PATH": tmp_path / "hub.sqlite",
        "UPLOADS_DIR": tmp_path / "uploads",
        "SECRET_KEY_FILE": tmp_path / ".secret_key",
        "TLS_HOSTNAME": "hub.valdev.me",
        "CERT_HELPER_SOCKET": str(tmp_path / "absent-helper.sock"),
        "TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
        # La planification Trivy ne démarre jamais dans les tests : elle est
        # testée par appels directs (`trivy_scheduler.run_due_sync`).
        "TRIVY_SCHEDULER_ENABLED": False,
    }


@pytest.fixture()
def app(tmp_path):
    application = create_app(_config(tmp_path))
    application.config.update(TESTING=True)
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def session_token(client) -> str | None:
    cookie = client.get_cookie("hub_session")
    return cookie.value if cookie else None


def session_csrf(client, app) -> str:
    token = session_token(client)
    assert token, "aucune session ouverte"
    connection = sqlite3.connect(app.config["DB_PATH"])
    try:
        row = connection.execute(
            "SELECT csrf_token FROM sessions WHERE token_hash = ?",
            (hashlib.sha256(token.encode("ascii")).hexdigest(),),
        ).fetchone()
    finally:
        connection.close()
    assert row, "session absente en base"
    return row[0]


def login(client, app, username: str = ADMIN_USERNAME, password: str = ADMIN_PASSWORD):
    """Connexion via HTTP ; retourne la réponse du POST /admin/login."""
    client.get("/admin/login")
    with client.session_transaction() as flask_session:
        preauth = flask_session.get("preauth_csrf")
    return client.post(
        "/admin/login",
        data={"username": username, "password": password, "_csrf": preauth},
        follow_redirects=False,
    )


def setup_admin(client, app, username: str = ADMIN_USERNAME, password: str = ADMIN_PASSWORD):
    client.get("/admin/setup")
    with client.session_transaction() as flask_session:
        preauth = flask_session.get("preauth_csrf")
    return client.post(
        "/admin/setup",
        data={"username": username, "password": password, "confirmation": password, "_csrf": preauth},
        follow_redirects=False,
    )


@pytest.fixture()
def admin(app, client):
    """Client HTTP authentifié (première configuration déjà effectuée)."""
    response = setup_admin(client, app)
    assert response.status_code == 302
    return client


def ensure_category(app, name: str) -> int:
    """Retourne l'id de la catégorie `name`, en la créant si nécessaire."""
    from app import auth as auth_module
    from app import catalog as catalog_module

    with app.app_context():
        connection = auth_module.db_connection()
        row = connection.execute(
            "SELECT id FROM categories WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
        if row is not None:
            return int(row["id"])
        created, error = catalog_module.create_category(connection, name)
        assert error is None, error
        assert created is not None
        return int(created["id"])


def create_catalog_app(app, **overrides) -> int:
    from app import auth as auth_module
    from app import catalog as catalog_module

    category_name = overrides.pop("category", "Fortinet")
    data = {
        "slug": "fortiflow",
        "name": "FortiFlow",
        "description": "Analyse de logs FortiGate.",
        "url": "https://fortiflow.valdev.me",
        "category_id": ensure_category(app, category_name),
        "status": "production",
    }
    data.update(overrides)
    with app.app_context():
        connection = auth_module.db_connection()
        app_id, error = catalog_module.create_app(connection, data)
        assert error is None, error
        assert app_id is not None
        return int(app_id)


# --- Helper certificat local (vraie socket, vrai protocole) --------------------


class FakeNginx:
    """Remplace NginxController : enregistre les appels et permet de simuler des échecs."""

    def __init__(self, *, fail_test_at: int | None = None, served_mismatch: bool = False):
        self.calls: list[str] = []
        self.fail_test_at = fail_test_at
        self.served_mismatch = served_mismatch
        self.test_count = 0
        self._served: str | None = None

    def set_served(self, fingerprint: str | None) -> None:
        self._served = fingerprint

    def test_config(self) -> None:
        self.calls.append("test_config")
        self.test_count += 1
        if self.fail_test_at is not None and self.test_count == self.fail_test_at:
            import hub_cert_helper

            raise hub_cert_helper.CertificateReloadError(
                "Nginx a refusé la configuration (nginx -t)."
            )

    def reload(self) -> None:
        self.calls.append("reload")

    def served_fingerprint(self) -> str | None:
        if self.served_mismatch:
            return "AA:BB:CC"
        return self._served

    def verify_served(self, expected_fingerprint: str, attempts: int = 5, delay: float = 0.4) -> None:
        self.calls.append("verify_served")
        if self.served_mismatch:
            import hub_cert_helper

            raise hub_cert_helper.CertificateReloadError(
                "Le certificat servi par Nginx ne correspond pas au certificat activé "
                "(vérification HTTPS échouée)."
            )


@pytest.fixture()
def helper(tmp_path):
    """Helper réel exposé par une vraie socket Unix, avec Nginx simulé."""
    import hub_cert_helper

    base = tmp_path / "helper"
    staging = base / "staging"
    staging.mkdir(parents=True)
    nginx = FakeNginx()
    processor = hub_cert_helper.CertHelperProcessor(
        hostname="hub.valdev.me",
        output_dir=base / "active",
        staging_dir=staging,
        allowed_uid=os.getuid(),
        allowed_gid=os.getgid(),
        nginx=nginx,
    )
    socket_path = base / "helper.sock"
    server = hub_cert_helper.CertHelperServer(socket_path, processor, socket_gid=None)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "socket": socket_path,
            "processor": processor,
            "server": server,
            "nginx": nginx,
            "output": base / "active",
            "staging": staging,
            "module": hub_cert_helper,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def cert_app(tmp_path, helper):
    """Application dont le client certificat pointe vers le helper réel."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    application = create_app(
        {
            "DATA_DIR": data_dir,
            "DB_PATH": data_dir / "hub.sqlite",
            "UPLOADS_DIR": data_dir / "uploads",
            "SECRET_KEY_FILE": data_dir / ".secret_key",
            "TLS_HOSTNAME": "hub.valdev.me",
            "CERT_HELPER_SOCKET": str(helper["socket"]),
            "TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
        }
    )
    application.config.update(TESTING=True)
    return application
