"""Landing page publique : contenu, filtres, ordre, images, santé."""

from __future__ import annotations

import io
import json
import sqlite3

from conftest import PNG_BYTES, create_catalog_app, ensure_category, session_csrf


def set_enabled(app, app_id: int, enabled: bool) -> None:
    connection = sqlite3.connect(app.config["DB_PATH"])
    connection.execute("UPDATE apps SET enabled = ? WHERE id = ?", (1 if enabled else 0, app_id))
    connection.commit()
    connection.close()


def test_empty_catalogue(app, client):
    page = client.get("/")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert "Aucun outil ne correspond" in body
    assert "0 application" in body


def test_lists_only_enabled_apps(app, client):
    enabled_id = create_catalog_app(app, slug="visible", name="Visible")
    hidden_id = create_catalog_app(app, slug="cachee", name="Cachee")
    set_enabled(app, hidden_id, False)
    body = client.get("/").get_data(as_text=True)
    assert "Visible" in body
    assert "Cachee" not in body
    assert enabled_id != hidden_id


def test_order_respected(app, client):
    create_catalog_app(app, slug="beta", name="Beta", position=20)
    create_catalog_app(app, slug="alpha", name="Alpha", position=10)
    body = client.get("/").get_data(as_text=True)
    assert body.index("Alpha") < body.index("Beta")


def test_category_filter_and_search(app, client):
    create_catalog_app(app, slug="flow", name="FortiFlow", category="Fortinet")
    create_catalog_app(app, slug="anon", name="FortiAnonymous", category="Sécurité")
    body = client.get("/?category=fortinet").get_data(as_text=True)
    assert "FortiFlow" in body and "FortiAnonymous" not in body
    body = client.get("/?q=anon").get_data(as_text=True)
    assert "FortiAnonymous" in body and "FortiFlow" not in body
    body = client.get("/?q=inexistant").get_data(as_text=True)
    assert "Aucun outil ne correspond" in body


def test_status_and_category_displayed(app, client):
    create_catalog_app(app, slug="beta", name="Beta", status="beta")
    body = client.get("/").get_data(as_text=True)
    assert "Bêta" in body
    assert "Fortinet" in body  # étiquette de catégorie


def test_image_served_and_cached(app, admin):
    csrf = session_csrf(admin, app)
    admin.post(
        "/admin/apps/new",
        data={
            "name": "Avec image",
            "slug": "avec-image",
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
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "image/png"
    assert "max-age" in response.headers.get("Cache-Control", "")
    landing = admin.get("/").get_data(as_text=True)
    assert f"/img/{image}" in landing


def test_image_name_validation(app, client):
    assert client.get("/img/pas-un-nom.png").status_code == 404
    assert client.get("/img/..%2F..%2Fetc%2Fpasswd").status_code == 404
    assert client.get("/img/" + "a" * 32 + ".gif").status_code == 404


def test_healthz(app, client):
    response = client.get("/healthz")
    assert response.status_code == 200
    payload = json.loads(response.get_data())
    assert payload["status"] == "ok"


def test_favicon_redirect(app, client):
    response = client.get("/favicon.ico")
    assert response.status_code == 302
    assert "favicon.svg" in response.headers["Location"]


def test_links_new_tab_setting(app, admin):
    create_catalog_app(app)
    body = admin.get("/").get_data(as_text=True)
    assert 'target="_blank"' in body
    csrf = session_csrf(admin, app)
    admin.post("/admin/settings/preferences", data={"_csrf": csrf})
    body = admin.get("/").get_data(as_text=True)
    assert 'target="_blank"' not in body
