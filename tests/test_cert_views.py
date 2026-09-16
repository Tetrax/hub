"""Intégration application ↔ helper réel (socket Unix, protocole complet)."""

from __future__ import annotations

import io
import re
from pathlib import Path

from conftest import (
    chain_certificates,
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


def test_certificate_page_proposes_both_import_methods(cert_app, helper):
    client = admin_client(cert_app)
    body = client.get("/admin/certificates").get_data(as_text=True)
    assert "PKCS#12 / PFX" in body and "recommandé" in body
    assert "PEM / CRT" in body
    assert 'action="/admin/certificates/validate-pkcs12"' in body
    assert 'action="/admin/certificates/validate"' in body
    assert 'type="radio" name="cert_method" id="method-pkcs12" checked' in body
    assert 'name="password"' in body and 'autocomplete="off"' in body
    assert "256 Ko maximum" in body
    # Les fichiers attendus sont annoncés (jamais de validation par extension seule côté serveur).
    assert 'accept=".p12,.pfx"' in body


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


# --- Import PKCS#12 / PFX -----------------------------------------------------

PFX_PASSWORD = "MotDePasse-PFX-2026"


def pfx_payload(
    bundle: bytes, filename: str = "bundle.p12", password: str | None = None
) -> dict[str, object]:
    payload: dict[str, object] = {"bundle": (io.BytesIO(bundle), filename)}
    if password is not None:
        payload["password"] = password
    return payload


def chained_pfx(*, password: str = "", with_root: bool = True) -> tuple[bytes, dict]:
    """Bundle PKCS#12 (feuille + intermédiaire + racine) et certificats attendus."""
    from test_certparse import build_pfx

    leaf_pem, key_pem, intermediate_pem, root_pem = chain_certificates()
    cas = [intermediate_pem] + ([root_pem] if with_root else [])
    bundle = build_pfx(
        leaf_pem=leaf_pem, key_pem=key_pem, cas=cas, password=password, name=b"hub.valdev.me"
    )
    return bundle, {
        "leaf": leaf_pem,
        "key": key_pem,
        "intermediate": intermediate_pem,
        "root": root_pem,
    }


def test_pkcs12_validate_then_activate_full_flow(cert_app, helper):
    client = admin_client(cert_app)
    csrf = session_csrf(client, cert_app)
    bundle, expected = chained_pfx(password=PFX_PASSWORD)

    response = client.post(
        "/admin/certificates/validate-pkcs12",
        data={**pfx_payload(bundle, "hub.pfx", PFX_PASSWORD), "_csrf": csrf},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    body = response.get_data()
    page = body.decode("utf-8")
    assert "prête à être activée" in page
    assert "PKCS#12" in page  # méthode d'import affichée dans le résumé
    assert "hub.valdev.me" in page
    assert not helper["output"].exists()  # rien n'est installé avant activation

    match = TICKET_RE.search(body)
    assert match, "ticket absent de la page"
    ticket = match.group(1).decode("ascii")

    response = client.post(
        "/admin/certificates/activate",
        data={"_csrf": csrf, "ticket": ticket},
        follow_redirects=True,
    )
    page = response.get_data(as_text=True)
    assert "Certificat activé" in page
    # La paire installée est exactement feuille + intermédiaire (racine exclue).
    installed = (helper["output"] / "fullchain.pem").read_bytes()
    assert installed == expected["leaf"] + expected["intermediate"]
    assert expected["root"] not in installed
    assert helper["nginx"].calls[:3] == ["test_config", "test_config", "reload"]
    status_page = client.get("/admin/certificates").get_data(as_text=True)
    assert "Certificat actif" in status_page
    # Chaîne = feuille + 1 intermédiaire (la racine serait comptée sinon).
    assert "<dt>Certificats dans la chaîne</dt><dd>2</dd>" in status_page


def test_pkcs12_without_password_full_flow(cert_app, helper):
    client = admin_client(cert_app)
    csrf = session_csrf(client, cert_app)
    bundle, expected = chained_pfx(password="")
    response = client.post(
        "/admin/certificates/validate-pkcs12",
        data={**pfx_payload(bundle, "sans-mot-de-passe.pfx"), "_csrf": csrf},
        content_type="multipart/form-data",
    )
    assert "prête à être activée" in response.get_data(as_text=True)
    match = TICKET_RE.search(response.get_data())
    assert match
    client.post(
        "/admin/certificates/activate",
        data={"_csrf": csrf, "ticket": match.group(1).decode("ascii")},
        follow_redirects=True,
    )
    assert (helper["output"] / "fullchain.pem").read_bytes() == (
        expected["leaf"] + expected["intermediate"]
    )


def test_pkcs12_wrong_password_is_rejected_and_secret_never_leaks(cert_app, helper, caplog):
    import logging

    client = admin_client(cert_app)
    csrf = session_csrf(client, cert_app)
    bundle, _ = chained_pfx(password=PFX_PASSWORD)
    wrong = "mauvais-mot-de-passe-xyz"
    with caplog.at_level(logging.DEBUG):
        response = client.post(
            "/admin/certificates/validate-pkcs12",
            data={**pfx_payload(bundle, "hub.p12", wrong), "_csrf": csrf},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
    page = response.get_data(as_text=True)
    assert "Impossible d" in page and "Vérifiez le mot de passe" in page
    assert wrong not in page
    assert PFX_PASSWORD not in page
    logs = "\n".join(record.getMessage() for record in caplog.records)
    assert wrong not in logs and PFX_PASSWORD not in logs
    assert not helper["output"].exists()


def test_pkcs12_rejects_pem_file(cert_app, helper):
    client = admin_client(cert_app)
    csrf = session_csrf(client, cert_app)
    leaf_pem, key_pem, _intermediate, _root = chain_certificates()
    response = client.post(
        "/admin/certificates/validate-pkcs12",
        data={**pfx_payload(leaf_pem, "certificat.pfx", ""), "_csrf": csrf},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    page = response.get_data(as_text=True)
    assert "utilisez la méthode" in page
    assert not helper["output"].exists()


def test_pkcs12_requires_csrf(cert_app, helper):
    client = admin_client(cert_app)
    bundle, _ = chained_pfx(password="p")
    response = client.post(
        "/admin/certificates/validate-pkcs12",
        data=pfx_payload(bundle, "hub.p12", "p"),
        content_type="multipart/form-data",
    )
    assert response.status_code == 403


def test_pkcs12_requires_file(cert_app, helper):
    client = admin_client(cert_app)
    csrf = session_csrf(client, cert_app)
    response = client.post(
        "/admin/certificates/validate-pkcs12",
        data={"_csrf": csrf},
        follow_redirects=True,
    )
    assert "est requis" in response.get_data(as_text=True)


def test_pkcs12_rejects_oversized_bundle(cert_app, helper):
    client = admin_client(cert_app)
    csrf = session_csrf(client, cert_app)
    limit = cert_app.config["CERT_BUNDLE_MAX_BYTES"]
    response = client.post(
        "/admin/certificates/validate-pkcs12",
        data={**pfx_payload(b"\x30\x82" + b"\x00" * limit, "gros.pfx", ""), "_csrf": csrf},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert "trop volumineux" in response.get_data(as_text=True)


def test_pem_route_accepts_der_certificate(cert_app, helper):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    client = admin_client(cert_app)
    csrf = session_csrf(client, cert_app)
    leaf_pem, key_pem, intermediate_pem, _root = chain_certificates()
    der = x509.load_pem_x509_certificate(leaf_pem).public_bytes(Encoding.DER)
    response = client.post(
        "/admin/certificates/validate",
        data={
            **upload_payload(der, key_pem, intermediate_pem),
            "_csrf": csrf,
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert "prête à être activée" in response.get_data(as_text=True)
    match = TICKET_RE.search(response.get_data())
    assert match
    client.post(
        "/admin/certificates/activate",
        data={"_csrf": csrf, "ticket": match.group(1).decode("ascii")},
        follow_redirects=True,
    )
    assert (helper["output"] / "fullchain.pem").read_bytes() == leaf_pem + intermediate_pem


def test_pem_route_rejects_encrypted_private_key(cert_app, helper):
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption,
        Encoding,
        PrivateFormat,
        load_pem_private_key,
    )

    client = admin_client(cert_app)
    csrf = session_csrf(client, cert_app)
    certificate, key_pem = leaf_certificate()
    encrypted = load_pem_private_key(key_pem, password=None).private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b"secret")
    )
    response = client.post(
        "/admin/certificates/validate",
        data={**upload_payload(certificate, encrypted), "_csrf": csrf},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert "ne doit pas être chiffrée" in response.get_data(as_text=True)
    assert not helper["output"].exists()


def test_pkcs12_import_leaves_no_file_behind(cert_app, helper, tmp_path):
    """Aucun bundle ni secret ne doit rester sur disque après l'import."""
    client = admin_client(cert_app)
    csrf = session_csrf(client, cert_app)
    bundle, _ = chained_pfx(password=PFX_PASSWORD)
    data_dir = Path(cert_app.config["DATA_DIR"])
    before = sorted(path.relative_to(data_dir) for path in data_dir.rglob("*"))
    client.post(
        "/admin/certificates/validate-pkcs12",
        data={**pfx_payload(bundle, "hub.p12", PFX_PASSWORD), "_csrf": csrf},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    after = sorted(path.relative_to(data_dir) for path in data_dir.rglob("*"))
    assert after == before
    assert not list(data_dir.rglob("*.p12")) and not list(data_dir.rglob("*.pfx"))
