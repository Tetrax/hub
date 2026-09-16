"""Défenses transverses : en-têtes, frontière proxy, information disclosure."""

from __future__ import annotations

from app import create_app

from conftest import ADMIN_PASSWORD, ensure_category, session_csrf, setup_admin


def test_security_headers_on_public_pages(app, client):
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "same-origin"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "Permissions-Policy" in response.headers
    assert "noindex" in response.headers["X-Robots-Tag"]
    assert "Strict-Transport-Security" not in response.headers  # pas en HTTP local


def test_hsts_only_from_trusted_proxy(app, client):
    response = client.get("/", headers={"X-Forwarded-Proto": "https"})
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000"


def test_forwarded_proto_ignored_from_untrusted_peer(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    application = create_app(
        {
            "DATA_DIR": data_dir,
            "DB_PATH": data_dir / "hub.sqlite",
            "UPLOADS_DIR": data_dir / "uploads",
            "SECRET_KEY_FILE": data_dir / ".secret_key",
            "TLS_HOSTNAME": "hub.valdev.me",
            "CERT_HELPER_SOCKET": str(tmp_path / "absent.sock"),
            "TRUSTED_PROXY_CIDRS": "192.0.2.0/24",  # le client de test (127.0.0.1) n'est pas de confiance
        }
    )
    application.config.update(TESTING=True)
    client = application.test_client()
    response = client.get("/", headers={"X-Forwarded-Proto": "https"})
    assert "Strict-Transport-Security" not in response.headers


def test_login_cookie_secure_behind_https(app, client):
    setup_admin(client, app)
    csrf = session_csrf(client, app)
    client.post("/admin/logout", data={"_csrf": csrf})
    client.get("/admin/login")
    with client.session_transaction() as flask_session:
        preauth = flask_session.get("preauth_csrf")
    response = client.post(
        "/admin/login",
        data={"username": "admin", "password": ADMIN_PASSWORD, "_csrf": preauth},
        headers={"X-Forwarded-Proto": "https"},
    )
    assert "Secure" in response.headers.get("Set-Cookie", "")


def test_preauth_cookie_secure_only_behind_trusted_https(app, client):
    """Le cookie de session Flask (pré-authentification) suit le schéma détecté."""
    setup_admin(client, app)  # sans admin, /admin/login redirige vers /admin/setup
    # Client neuf (aucun cookie) : HTTP local → cookie posé, mais sans Secure
    # (le login doit rester utilisable en HTTP interne).
    fresh = app.test_client()
    cookie = fresh.get("/admin/login").headers.get("Set-Cookie", "")
    assert cookie, "un cookie de session Flask est attendu"
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert "Secure" not in cookie

    # Proxy de confiance déclarant HTTPS → cookie Secure.
    fresh_https = app.test_client()
    response = fresh_https.get("/admin/login", headers={"X-Forwarded-Proto": "https"})
    assert "Secure" in response.headers.get("Set-Cookie", "")


def test_preauth_cookie_not_secure_from_untrusted_proxy(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    application = create_app(
        {
            "DATA_DIR": data_dir,
            "DB_PATH": data_dir / "hub.sqlite",
            "UPLOADS_DIR": data_dir / "uploads",
            "SECRET_KEY_FILE": data_dir / ".secret_key",
            "TLS_HOSTNAME": "hub.valdev.me",
            "CERT_HELPER_SOCKET": str(tmp_path / "absent.sock"),
            "TRUSTED_PROXY_CIDRS": "192.0.2.0/24",  # 127.0.0.1 n'est pas de confiance
        }
    )
    application.config.update(TESTING=True)
    setup_admin(application.test_client(), application)
    fresh = application.test_client()
    response = fresh.get("/admin/login", headers={"X-Forwarded-Proto": "https"})
    cookie = response.headers.get("Set-Cookie", "")
    assert cookie and "Secure" not in cookie


def test_error_page_has_no_internals(app, client):
    body = client.get("/introuvable").get_data(as_text=True)
    assert "404" in body
    assert "Traceback" not in body
    assert "/home/" not in body and "site-packages" not in body


def test_admin_pages_carry_noindex(app, admin):
    response = admin.get("/admin/")
    assert "noindex" in response.headers["X-Robots-Tag"]


def test_settings_page_hides_password(app, admin):
    body = admin.get("/admin/settings").get_data(as_text=True)
    assert ADMIN_PASSWORD not in body


def test_uploaded_asset_served_with_image_type(app, admin):
    """Un screenshot est servi comme image, jamais comme HTML exécutable."""
    import io
    import sqlite3

    from conftest import PNG_BYTES

    csrf = session_csrf(admin, app)
    admin.post(
        "/admin/apps/new",
        data={
            "name": "Image test",
            "slug": "image-test",
            "description": "",
            "url": "https://exemple.valdev.me",
            "category_id": ensure_category(app, "Autres"),
            "status": "production",
            "_csrf": csrf,
            "image": (io.BytesIO(PNG_BYTES), "x.png"),
        },
        content_type="multipart/form-data",
    )
    connection = sqlite3.connect(app.config["DB_PATH"])
    image = connection.execute("SELECT image FROM apps").fetchone()[0]
    connection.close()
    response = admin.get(f"/img/{image}")
    assert response.headers["Content-Type"] == "image/png"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_helper_socket_never_exposed(app, client):
    """Aucune page publique ne doit exposer de matériel de clé privée."""
    for path in ("/", "/admin/certificates", "/admin/"):
        body = client.get(path).get_data(as_text=True)
        assert "BEGIN PRIVATE KEY" not in body
        assert "BEGIN CERTIFICATE" not in body
