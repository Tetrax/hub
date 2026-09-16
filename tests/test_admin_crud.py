"""CRUD du catalogue via /admin : création, édition, ordre, visibilité, images."""

from __future__ import annotations

import io
import sqlite3
from pathlib import Path

from conftest import JPEG_LIKE, PNG_BYTES, create_catalog_app, session_csrf


def make_payload(**overrides) -> dict:
    data = {
        "name": "FortiAnonymous",
        "slug": "fortianonymous",
        "description": "Expurgation locale de configurations FortiGate.",
        "url": "https://fortianonymous.valdev.me",
        "category": "Sécurité",
        "status": "production",
    }
    data.update(overrides)
    return data


def post_new(client, app, **overrides):
    csrf = session_csrf(client, app)
    return client.post(
        "/admin/apps/new",
        data={**make_payload(**overrides), "_csrf": csrf},
        follow_redirects=False,
    )


def test_create_app(app, admin):
    response = post_new(admin, app)
    assert response.status_code == 302
    landing = admin.get("/").get_data(as_text=True)
    assert "FortiAnonymous" in landing
    assert "https://fortianonymous.valdev.me" in landing


def test_create_rejects_dangerous_url(app, admin):
    response = post_new(admin, app, url="javascript:alert(1)")
    assert response.status_code == 200
    assert "http:// et https://" in response.get_data(as_text=True)
    landing = admin.get("/").get_data(as_text=True)
    assert "javascript" not in landing


def test_create_rejects_url_with_credentials(app, admin):
    response = post_new(admin, app, url="https://user:pass@example.com/")
    assert response.status_code == 200
    assert "identifiants" in response.get_data(as_text=True)


def test_create_rejects_duplicate_slug(app, admin):
    assert post_new(admin, app).status_code == 302
    response = post_new(admin, app, name="Autre", url="https://autre.valdev.me")
    assert response.status_code == 200
    assert "déjà utilisé" in response.get_data(as_text=True)


def test_create_generates_slug_from_name(app, admin):
    csrf = session_csrf(admin, app)
    response = admin.post(
        "/admin/apps/new",
        data={
            "name": "Éditeur Réseau Interne",
            "slug": "",
            "description": "",
            "url": "https://interne.valdev.me",
            "category": "Interne",
            "status": "beta",
            "_csrf": csrf,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    connection = sqlite3.connect(app.config["DB_PATH"])
    row = connection.execute("SELECT slug FROM apps").fetchone()
    connection.close()
    assert row[0] == "editeur-reseau-interne"


def test_edit_app(app, admin):
    create_catalog_app(app)
    csrf = session_csrf(admin, app)
    response = admin.post(
        "/admin/apps/1/edit",
        data={
            "name": "FortiFlow v1",
            "slug": "fortiflow",
            "description": "Mise à jour.",
            "url": "https://fortiflow.valdev.me",
            "category": "Fortinet",
            "status": "maintenance",
            "_csrf": csrf,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    page = admin.get("/admin/apps").get_data(as_text=True)
    assert "FortiFlow v1" in page
    assert "Maintenance" in page


def test_toggle_hides_from_landing(app, admin):
    app_id = create_catalog_app(app)
    csrf = session_csrf(admin, app)
    admin.post(f"/admin/apps/{app_id}/toggle", data={"_csrf": csrf})
    assert "FortiFlow" not in admin.get("/").get_data(as_text=True)
    page = admin.get("/admin/apps").get_data(as_text=True)
    assert "Masquée" in page
    admin.post(f"/admin/apps/{app_id}/toggle", data={"_csrf": csrf})
    assert "FortiFlow" in admin.get("/").get_data(as_text=True)


def test_move_reorders(app, admin):
    first = create_catalog_app(app, slug="a", name="Alpha", position=10)
    second = create_catalog_app(app, slug="b", name="Beta", position=20)
    csrf = session_csrf(admin, app)
    admin.post(f"/admin/apps/{second}/move", data={"_csrf": csrf, "direction": "up"})
    landing = admin.get("/").get_data(as_text=True)
    assert landing.index("Beta") < landing.index("Alpha")
    admin.post(f"/admin/apps/{second}/move", data={"_csrf": csrf, "direction": "down"})
    landing = admin.get("/").get_data(as_text=True)
    assert landing.index("Alpha") < landing.index("Beta")
    assert first != second


def test_delete_app_and_image(app, admin):
    csrf = session_csrf(admin, app)
    response = admin.post(
        "/admin/apps/new",
        data={
            **make_payload(),
            "_csrf": csrf,
            "image": (io.BytesIO(PNG_BYTES), "capture.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert response.status_code == 302
    connection = sqlite3.connect(app.config["DB_PATH"])
    image = connection.execute("SELECT image FROM apps").fetchone()[0]
    connection.close()
    uploads_dir = Path(app.config["UPLOADS_DIR"])
    assert (uploads_dir / image).is_file()
    response = admin.post(
        "/admin/apps/1/delete",
        data={"_csrf": csrf, "confirm_delete": "1"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert not (uploads_dir / image).exists()
    assert "FortiAnonymous" not in admin.get("/").get_data(as_text=True)


def test_delete_requires_confirmation(app, admin):
    app_id = create_catalog_app(app)
    csrf = session_csrf(admin, app)
    response = admin.post(
        f"/admin/apps/{app_id}/delete", data={"_csrf": csrf}, follow_redirects=True
    )
    assert "confirmation manquante" in response.get_data(as_text=True)
    assert "FortiFlow" in admin.get("/").get_data(as_text=True)


def test_upload_replaces_previous_image(app, admin):
    csrf = session_csrf(admin, app)
    admin.post(
        "/admin/apps/new",
        data={**make_payload(), "_csrf": csrf, "image": (io.BytesIO(PNG_BYTES), "a.png")},
        content_type="multipart/form-data",
    )
    connection = sqlite3.connect(app.config["DB_PATH"])
    first_image = connection.execute("SELECT image FROM apps").fetchone()[0]
    connection.close()
    admin.post(
        "/admin/apps/1/edit",
        data={
            **make_payload(),
            "_csrf": csrf,
            "image": (io.BytesIO(JPEG_LIKE), "b.jpg"),
        },
        content_type="multipart/form-data",
    )
    connection = sqlite3.connect(app.config["DB_PATH"])
    second_image = connection.execute("SELECT image FROM apps").fetchone()[0]
    connection.close()
    uploads_dir = Path(app.config["UPLOADS_DIR"])
    assert second_image != first_image
    assert (uploads_dir / second_image).is_file()
    assert not (uploads_dir / first_image).exists()
    served = admin.get(f"/img/{second_image}")
    assert served.status_code == 200 and served.headers["Content-Type"] == "image/jpeg"


def test_remove_image_checkbox(app, admin):
    csrf = session_csrf(admin, app)
    admin.post(
        "/admin/apps/new",
        data={**make_payload(), "_csrf": csrf, "image": (io.BytesIO(PNG_BYTES), "a.png")},
        content_type="multipart/form-data",
    )
    connection = sqlite3.connect(app.config["DB_PATH"])
    image = connection.execute("SELECT image FROM apps").fetchone()[0]
    connection.close()
    admin.post(
        "/admin/apps/1/edit",
        data={**make_payload(), "_csrf": csrf, "remove_image": "1"},
        content_type="multipart/form-data",
    )
    connection = sqlite3.connect(app.config["DB_PATH"])
    assert connection.execute("SELECT image FROM apps").fetchone()[0] is None
    connection.close()
    assert not (Path(app.config["UPLOADS_DIR"]) / image).exists()


def test_spoofed_image_rejected(app, admin):
    csrf = session_csrf(admin, app)
    response = admin.post(
        "/admin/apps/new",
        data={
            **make_payload(),
            "_csrf": csrf,
            "image": (io.BytesIO(b"<script>alert(1)</script>"), "capture.png"),
        },
        content_type="multipart/form-data",
    )
    assert "Format non pris en charge" in response.get_data(as_text=True)
    connection = sqlite3.connect(app.config["DB_PATH"])
    count = connection.execute("SELECT COUNT(*) FROM apps").fetchone()[0]
    connection.close()
    assert count == 0


def test_oversized_image_rejected(app, admin):
    csrf = session_csrf(admin, app)
    big = PNG_BYTES + b"\x00" * (4 * 1024 * 1024)
    response = admin.post(
        "/admin/apps/new",
        data={**make_payload(), "_csrf": csrf, "image": (io.BytesIO(big), "big.png")},
        content_type="multipart/form-data",
    )
    assert "trop volumineux" in response.get_data(as_text=True)


def test_names_are_escaped(app, admin):
    response = post_new(admin, app, name='<script>alert("xss")</script>', slug="xss-test")
    assert response.status_code == 302
    landing = admin.get("/").get_data(as_text=True)
    assert '<script>alert("xss")</script>' not in landing
    assert "&lt;script&gt;" in landing


def test_admin_dashboard_stats(app, admin):
    create_catalog_app(app)
    create_catalog_app(app, slug="beta", name="Beta")
    page = admin.get("/admin/").get_data(as_text=True)
    assert "Tableau de bord" in page
    assert "Applications au total" in page
