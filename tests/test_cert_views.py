"""Intégration application ↔ helper réel (socket Unix, protocole complet)."""

from __future__ import annotations

import io
import re

from conftest import (
    leaf_certificate,
    login,
    session_csrf,
    setup_admin,
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
)

TICKET_RE = re.compile(rb'name="ticket" value="([A-Za-z0-9_-]+)"')


def admin_client(application):
    client = application.test_client()
    response = setup_admin(
        client, application, username=ADMIN_USERNAME, password=ADMIN_PASSWORD
    )
    assert response.status_code == 302
    return client


def upload_payload(certificate: bytes, key: bytes, chain: bytes | None = None) -> dict:
    payload = {
        "certificate": (io.BytesIO(certificate), "certificate.pem"),
        "private_key": (io.BytesIO(key), "private.key"),
    }
    if chain:
        payload["chain"] = (io.BytesIO(chain), "chain.pem")
    return payload


def test_certificate_page_without_active_pair(cert_app, helper):
    client = admin_client(cert_app)
    page = client.get("/admin/certificates")
    assert page.status_code == 200
    assert "Aucun certificat géré" in page.get_data(as_text=True)


def test_validate_then_activate_full_flow(cert_app, helper):
    client = admin_client(cert_app)
    csrf = session_csrf(client, cert_app)
    certificate, key = leaf_certificate()
    response = client.post(
        "/admin/certificates/validate",
        data={**upload_payload(certificate, key), "_csrf": csrf},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    body = response.get_data()
    assert "prête à être activée" in response.get_data(as_text=True)
    match = TICKET_RE.search(body)
    assert match, "ticket absent de la page"
    ticket = match.group(1).decode("ascii")

    # la paire est en attente côté helper, rien n'est encore actif
    assert not helper["output"].exists()

    response = client.post(
        "/admin/certificates/activate",
        data={"_csrf": csrf, "ticket": ticket},
        follow_redirects=True,
    )
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Certificat activé" in page
    assert "Nginx a été testé" in page
    assert (helper["output"] / "fullchain.pem").read_bytes() == certificate
    assert helper["nginx"].calls[:3] == ["test_config", "test_config", "reload"]

    # le certificat actif est maintenant affiché
    page = client.get("/admin/certificates").get_data(as_text=True)
    assert "hub.valdev.me" in page
    assert "Jours restants" in page


def test_validate_rejects_foreign_key(cert_app, helper):
    client = admin_client(cert_app)
    csrf = session_csrf(client, cert_app)
    certificate, _key = leaf_certificate()
    from conftest import make_key, private_key_pem

    other_key = private_key_pem(make_key())
    response = client.post(
        "/admin/certificates/validate",
        data={**upload_payload(certificate, other_key), "_csrf": csrf},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    page = response.get_data(as_text=True)
    assert "Validation refusée" in page
    assert not helper["output"].exists()


def test_activate_rejects_stale_ticket(cert_app, helper):
    client = admin_client(cert_app)
    csrf = session_csrf(client, cert_app)
    response = client.post(
        "/admin/certificates/activate",
        data={"_csrf": csrf, "ticket": "ticket-inconnu-" + "x" * 30},
        follow_redirects=True,
    )
    assert "Validation introuvable" in response.get_data(as_text=True)


def test_validate_requires_csrf(cert_app, helper):
    client = admin_client(cert_app)
    certificate, key = leaf_certificate()
    response = client.post(
        "/admin/certificates/validate",
        data=upload_payload(certificate, key),
        content_type="multipart/form-data",
    )
    assert response.status_code == 403


def test_activate_after_db_expiry(cert_app, helper):
    import sqlite3

    client = admin_client(cert_app)
    csrf = session_csrf(client, cert_app)
    certificate, key = leaf_certificate()
    response = client.post(
        "/admin/certificates/validate",
        data={**upload_payload(certificate, key), "_csrf": csrf},
        content_type="multipart/form-data",
    )
    match = TICKET_RE.search(response.get_data())
    assert match, "ticket absent"
    ticket = match.group(1).decode("ascii")
    connection = sqlite3.connect(cert_app.config["DB_PATH"])
    connection.execute("UPDATE cert_validations SET expires_at = '2000-01-01T00:00:00Z'")
    connection.commit()
    connection.close()
    response = client.post(
        "/admin/certificates/activate",
        data={"_csrf": csrf, "ticket": ticket},
        follow_redirects=True,
    )
    assert "Validation expirée" in response.get_data(as_text=True)
