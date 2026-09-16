"""Catégories administrables : CRUD, doublons, réassignation, filtres publics."""

from __future__ import annotations

import sqlite3

from conftest import create_catalog_app, ensure_category, session_csrf


def category_rows(app) -> list[dict]:
    connection = sqlite3.connect(app.config["DB_PATH"])
    connection.row_factory = sqlite3.Row
    rows = [
        dict(row)
        for row in connection.execute(
            "SELECT * FROM categories ORDER BY position ASC, name COLLATE NOCASE ASC"
        )
    ]
    connection.close()
    return rows


def find_category(app, name: str) -> dict | None:
    for row in category_rows(app):
        if row["name"].casefold() == name.casefold():
            return row
    return None


def category_id(app, name: str) -> int:
    row = find_category(app, name)
    assert row is not None, f"catégorie attendue absente : {name}"
    return int(row["id"])


def create_category(client, app, name: str):
    return client.post(
        "/admin/categories/create",
        data={"name": name, "_csrf": session_csrf(client, app)},
        follow_redirects=False,
    )


def test_fallback_category_exists(app):
    fallback = find_category(app, "Autres")
    assert fallback is not None
    assert fallback["is_fallback"] == 1
    assert fallback["slug"] == "autres"


def test_create_category(app, admin):
    response = create_category(admin, app, "Réseau")
    assert response.status_code == 302
    row = find_category(app, "Réseau")
    assert row is not None
    assert row["slug"] == "reseau"
    assert row["is_fallback"] == 0
    page = admin.get("/admin/categories").get_data(as_text=True)
    assert "Réseau" in page
    assert "0 application" in page


def test_create_category_trims_and_rejects_duplicates(app, admin):
    create_category(admin, app, "Réseau")
    create_category(admin, app, "  réseau  ")
    page = admin.get("/admin/categories").get_data(as_text=True)
    assert "existe déjà" in page
    matches = [row for row in category_rows(app) if row["name"].casefold() == "réseau"]
    assert len(matches) == 1


def test_create_category_rejects_invalid_names(app, admin):
    for name in ("", "   ", "x" * 41):
        create_category(admin, app, name)
    page = admin.get("/admin/categories").get_data(as_text=True)
    assert "obligatoire" in page or "trop longue" in page
    assert find_category(app, "x" * 41) is None


def test_rename_category(app, admin):
    create_catalog_app(app, slug="anon", name="FortiAnonymous", category="Sécurité")
    securite_id = category_id(app, "Sécurité")
    response = admin.post(
        f"/admin/categories/{securite_id}/rename",
        data={"name": "Sécurité offensive", "_csrf": session_csrf(admin, app)},
        follow_redirects=False,
    )
    assert response.status_code == 302
    renamed = find_category(app, "Sécurité offensive")
    assert renamed is not None
    assert renamed["id"] == securite_id
    # L'application reste associée à la même catégorie.
    assert "Sécurité offensive" in admin.get("/admin/apps").get_data(as_text=True)


def test_rename_category_rejects_duplicate(app, admin):
    create_category(admin, app, "Réseau")
    interne_id = ensure_category(app, "Interne")
    admin.post(
        f"/admin/categories/{interne_id}/rename",
        data={"name": "Réseau", "_csrf": session_csrf(admin, app)},
        follow_redirects=False,
    )
    assert find_category(app, "Interne") is not None


def test_delete_empty_category(app, admin):
    create_category(admin, app, "Réseau")
    response = admin.post(
        f"/admin/categories/{category_id(app, 'Réseau')}/delete",
        data={"_csrf": session_csrf(admin, app)},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert find_category(app, "Réseau") is None


def test_delete_used_category_requires_reassignment(app, admin):
    create_catalog_app(app, slug="flow", name="FortiFlow", category="Fortinet")
    response = admin.post(
        f"/admin/categories/{category_id(app, 'Fortinet')}/delete",
        data={"_csrf": session_csrf(admin, app)},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert find_category(app, "Fortinet") is not None
    page = admin.get("/admin/categories").get_data(as_text=True)
    assert "choisissez une catégorie de destination" in page


def test_delete_confirmation_page_lists_apps(app, admin):
    create_catalog_app(app, slug="flow", name="FortiFlow", category="Fortinet")
    page = admin.get(f"/admin/categories/{category_id(app, 'Fortinet')}/delete").get_data(
        as_text=True
    )
    assert "FortiFlow" in page
    assert "Réassigner et supprimer" in page


def test_delete_used_category_with_reassignment(app, admin):
    create_catalog_app(app, slug="flow", name="FortiFlow", category="Fortinet")
    create_catalog_app(app, slug="jox", name="JOX", category="Fortinet")
    create_catalog_app(app, slug="anon", name="FortiAnonymous", category="Sécurité")
    fallback_id = category_id(app, "Autres")
    response = admin.post(
        f"/admin/categories/{category_id(app, 'Fortinet')}/delete",
        data={"reassign_to": str(fallback_id), "_csrf": session_csrf(admin, app)},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert find_category(app, "Fortinet") is None
    connection = sqlite3.connect(app.config["DB_PATH"])
    moved = connection.execute(
        "SELECT COUNT(*) FROM apps WHERE category_id = ?", (fallback_id,)
    ).fetchone()[0]
    total = connection.execute("SELECT COUNT(*) FROM apps").fetchone()[0]
    orphans = connection.execute(
        "SELECT COUNT(*) FROM apps WHERE category_id IS NULL"
    ).fetchone()[0]
    connection.close()
    assert moved == 2
    assert total == 3  # aucune application perdue
    assert orphans == 0  # aucune référence cassée


def test_fallback_category_is_protected(app, admin):
    fallback_id = category_id(app, "Autres")
    admin.post(
        f"/admin/categories/{fallback_id}/delete",
        data={"_csrf": session_csrf(admin, app)},
        follow_redirects=False,
    )
    assert find_category(app, "Autres") is not None
    page = admin.get("/admin/categories").get_data(as_text=True)
    assert "ne peut pas être supprimée" in page
    assert "Catégorie de repli protégée" in page


def test_fallback_category_cannot_be_renamed(app, admin):
    fallback_id = category_id(app, "Autres")
    response = admin.post(
        f"/admin/categories/{fallback_id}/rename",
        data={"name": "Divers", "_csrf": session_csrf(admin, app)},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert find_category(app, "Autres") is not None
    assert find_category(app, "Divers") is None
    page = admin.get("/admin/categories").get_data(as_text=True)
    assert "ne peut pas être renommée" in page
    # Le champ de renommage n'est pas proposé pour la catégorie de repli.
    assert f'id="cat-name-{fallback_id}"' not in page


def test_category_order_is_editable(app, admin):
    create_category(admin, app, "Réseau")
    reseau_id = category_id(app, "Réseau")
    autres_id = category_id(app, "Autres")
    before = {row["id"]: row["position"] for row in category_rows(app)}
    assert before[reseau_id] > before[autres_id]
    response = admin.post(
        f"/admin/categories/{reseau_id}/move",
        data={"direction": "up", "_csrf": session_csrf(admin, app)},
        follow_redirects=False,
    )
    assert response.status_code == 302
    after = {row["id"]: row["position"] for row in category_rows(app)}
    assert after[reseau_id] < after[autres_id]  # remontée effective


def test_create_category_requires_csrf_and_session(app, client, admin):
    anonymous = app.test_client()  # client distinct, sans cookie de session
    response = anonymous.post("/admin/categories/create", data={"name": "Sans session"})
    assert response.status_code == 302
    assert "/admin/login" in response.headers.get("Location", "")
    assert find_category(app, "Sans session") is None
    response = admin.post(
        "/admin/categories/create", data={"name": "Sans CSRF"}, follow_redirects=False
    )
    assert response.status_code == 403
    assert find_category(app, "Sans CSRF") is None


def test_quick_create_category_json(app, admin):
    csrf = session_csrf(admin, app)
    response = admin.post(
        "/admin/categories/quick-create",
        data={"name": "Utils", "_csrf": csrf},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["category"]["name"] == "Utils"
    assert payload["category"]["id"] == category_id(app, "Utils")
    duplicate = admin.post(
        "/admin/categories/quick-create",
        data={"name": "utils", "_csrf": csrf},
        headers={"Accept": "application/json"},
    )
    assert duplicate.status_code == 400
    assert duplicate.get_json()["ok"] is False


def test_quick_create_requires_csrf(app, admin):
    response = admin.post(
        "/admin/categories/quick-create",
        data={"name": "Sans jeton"},
        headers={"Accept": "application/json"},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert find_category(app, "Sans jeton") is None


def test_app_form_uses_category_select(app, admin):
    create_category(admin, app, "Réseau")
    page = admin.get("/admin/apps/new").get_data(as_text=True)
    assert 'id="category_id" name="category_id"' in page
    assert ">Réseau<" in page
    assert ">Autres<" in page
    assert "data-quick-add-toggle" in page


def test_app_form_rejects_unknown_category(app, admin):
    response = admin.post(
        "/admin/apps/new",
        data={
            "name": "Sans catégorie",
            "slug": "sans-categorie",
            "description": "",
            "url": "https://exemple.valdev.me",
            "category_id": "9999",
            "status": "production",
            "_csrf": session_csrf(admin, app),
        },
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "Catégorie inconnue" in response.get_data(as_text=True)
    assert "Sans catégorie" not in admin.get("/").get_data(as_text=True)


def test_app_created_with_new_category_gets_its_filter(app, admin):
    csrf = session_csrf(admin, app)
    response = admin.post(
        "/admin/apps/new",
        data={
            "name": "Vysion",
            "slug": "vysion",
            "description": "",
            "url": "https://vysion.valdev.me",
            "category_id": str(ensure_category(app, "Réseau")),
            "status": "production",
            "_csrf": csrf,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    landing = admin.get("/").get_data(as_text=True)
    assert 'data-category="reseau"' in landing
    assert "Vysion" in landing


def test_new_category_feeds_public_filter(app, client):
    create_catalog_app(app, slug="flow", name="FortiFlow", category="Fortinet")
    create_catalog_app(app, slug="vysion", name="Vysion", category="Réseau")
    body = client.get("/").get_data(as_text=True)
    assert 'data-category="reseau"' in body  # filtre généré automatiquement
    assert 'data-category="fortinet"' in body
    filtered = client.get("/?category=reseau").get_data(as_text=True)
    assert "Vysion" in filtered and "FortiFlow" not in filtered


def test_empty_category_absent_from_landing(app, client):
    create_catalog_app(app, slug="flow", name="FortiFlow", category="Fortinet")
    ensure_category(app, "Réseau")  # créée mais utilisée par aucune application
    body = client.get("/").get_data(as_text=True)
    assert "FortiFlow" in body
    assert "Réseau" not in body
    assert 'data-category="reseau"' not in body


def test_category_of_disabled_app_hidden_from_landing(app, client):
    ensure_category(app, "Réseau")
    app_id = create_catalog_app(app, slug="vysion", name="Vysion", category="Réseau")
    assert 'data-category="reseau"' in client.get("/").get_data(as_text=True)
    connection = sqlite3.connect(app.config["DB_PATH"])
    connection.execute("UPDATE apps SET enabled = 0 WHERE id = ?", (app_id,))
    connection.commit()
    connection.close()
    assert 'data-category="reseau"' not in client.get("/").get_data(as_text=True)


def test_category_usage_counts_include_disabled_apps(app, admin):
    app_id = create_catalog_app(app, slug="flow", name="FortiFlow", category="Fortinet")
    connection = sqlite3.connect(app.config["DB_PATH"])
    connection.execute("UPDATE apps SET enabled = 0 WHERE id = ?", (app_id,))
    connection.commit()
    connection.close()
    page = admin.get("/admin/categories").get_data(as_text=True)
    assert "1 application" in page


def test_categories_nav_link_in_admin(app, admin):
    page = admin.get("/admin/").get_data(as_text=True)
    assert 'href="/admin/categories"' in page
    assert "Catégories" in page
