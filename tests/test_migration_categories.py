"""Migration v1 → v2 : `apps.category` (texte) devient une entité `categories`.

Aucune application, aucune catégorie et aucune association ne doit être perdue.
"""

from __future__ import annotations

import sqlite3

import pytest

from app import db

LEGACY_SCHEMA = """
CREATE TABLE apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL,
    image TEXT,
    category TEXT NOT NULL DEFAULT 'Autres',
    position INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'production'
        CHECK (status IN ('production', 'beta', 'maintenance', 'indisponible')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

LEGACY_APPS = [
    # slug, name, description, url, image, category, position, enabled, status
    ("fortiupgrade", "FortiUpgrade", "Parcours de mise à niveau.", "https://fortiupgrade.valdev.me",
     "aaa.webp", "Fortinet", 10, 1, "production"),
    ("fortiflow", "FortiFlow", "Segmentation.", "https://fortiflow.valdev.me",
     "bbb.webp", "  Fortinet  ", 20, 1, "production"),
    ("fortianonymous", "FortiAnonymous", "Expurgation.", "https://fortianonymous.valdev.me",
     None, "Sécurité", 30, 1, "beta"),
    ("vysion", "Vysion", "Inventaire.", "https://vysion.valdev.me",
     "ccc.webp", "autrES", 40, 0, "maintenance"),
    ("bricole", "Bricole", "Interne.", "https://bricole.valdev.me",
     None, "", 50, 1, "production"),
    ("legacy", "Legacy", "Ancienne app.", "https://legacy.valdev.me",
     None, "Interne", 60, 1, "indisponible"),
]

TIMESTAMP = "2026-09-01T10:00:00Z"


def build_legacy_db(path) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(LEGACY_SCHEMA)
    for slug, name, description, url, image, category, position, enabled, status in LEGACY_APPS:
        connection.execute(
            "INSERT INTO apps (slug, name, description, url, image, category, position, enabled, "
            "status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (slug, name, description, url, image, category, position, enabled, status,
             TIMESTAMP, TIMESTAMP),
        )
    connection.execute("INSERT INTO settings (key, value) VALUES ('open_links_new_tab', '1')")
    connection.commit()
    connection.close()


def rows(path, query, params=()):
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    result = [dict(row) for row in connection.execute(query, params)]
    connection.close()
    return result


@pytest.fixture()
def migrated(tmp_path):
    path = tmp_path / "legacy.sqlite"
    build_legacy_db(path)
    db.init_db(path)
    return path


def test_migration_keeps_every_application(migrated):
    apps = rows(migrated, "SELECT * FROM apps ORDER BY position ASC")
    assert len(apps) == len(LEGACY_APPS)
    by_slug = {app["slug"]: app for app in apps}
    for slug, name, description, url, image, _category, position, enabled, status in LEGACY_APPS:
        app = by_slug[slug]
        assert app["name"] == name
        assert app["description"] == description
        assert app["url"] == url
        assert app["image"] == image
        assert app["position"] == position
        assert app["enabled"] == enabled
        assert app["status"] == status
        assert app["created_at"] == TIMESTAMP
        assert app["updated_at"] == TIMESTAMP
        assert app["category_id"] is not None


def test_migration_creates_categories_without_loss(migrated):
    categories = rows(migrated, "SELECT * FROM categories ORDER BY position ASC")
    names = [category["name"] for category in categories]
    # « Autres » (repli) d'abord, puis les catégories existantes dans l'ordre d'apparition.
    assert names[0] == "Autres"
    assert set(names) == {"Autres", "Fortinet", "Sécurité", "Interne"}
    fallback = categories[0]
    assert fallback["is_fallback"] == 1
    assert sum(1 for category in categories if category["is_fallback"]) == 1
    # Les variantes de casse et d'espaces ne créent pas de doublon.
    assert sum(1 for name in names if name.casefold() == "fortinet") == 1
    slugs = [category["slug"] for category in categories]
    assert sorted(slugs) == sorted(set(slugs))


def test_migration_preserves_associations(migrated):
    apps = {app["slug"]: app for app in rows(migrated, "SELECT * FROM apps")}
    categories = {category["id"]: category["name"] for category in
                  rows(migrated, "SELECT * FROM categories")}
    assert categories[apps["fortiupgrade"]["category_id"]] == "Fortinet"
    assert categories[apps["fortiflow"]["category_id"]] == "Fortinet"
    assert categories[apps["fortianonymous"]["category_id"]] == "Sécurité"
    assert categories[apps["vysion"]["category_id"]] == "Autres"
    assert categories[apps["bricole"]["category_id"]] == "Autres"
    assert categories[apps["legacy"]["category_id"]] == "Interne"


def test_migration_schema_is_v2(migrated):
    columns = {row["name"] for row in rows(migrated, "PRAGMA table_info(apps)")}
    assert "category_id" in columns
    assert "category" not in columns
    assert rows(migrated, "PRAGMA user_version")[0]["user_version"] == db.SCHEMA_VERSION
    assert rows(migrated, "PRAGMA foreign_key_check") == []


def test_migration_is_idempotent(migrated):
    before = rows(migrated, "SELECT * FROM categories ORDER BY id")
    db.init_db(migrated)
    db.init_db(migrated)
    after = rows(migrated, "SELECT * FROM categories ORDER BY id")
    assert [row["id"] for row in before] == [row["id"] for row in after]
    assert len(rows(migrated, "SELECT * FROM apps")) == len(LEGACY_APPS)


def test_migration_of_empty_catalogue(tmp_path):
    path = tmp_path / "empty.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript(LEGACY_SCHEMA)
    connection.commit()
    connection.close()
    db.init_db(path)
    categories = rows(path, "SELECT * FROM categories")
    assert len(categories) == 1
    assert categories[0]["name"] == "Autres"
    assert categories[0]["is_fallback"] == 1
    assert rows(path, "SELECT * FROM apps") == []


def test_foreign_keys_protect_applications(migrated):
    """Supprimer une catégorie utilisée par SQL brut doit être refusé."""
    connection = sqlite3.connect(migrated)
    connection.execute("PRAGMA foreign_keys=ON")
    category_id = connection.execute(
        "SELECT id FROM categories WHERE name = 'Fortinet'"
    ).fetchone()[0]
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("DELETE FROM categories WHERE id = ?", (category_id,))
    connection.close()


def test_fresh_database_uses_v2_schema(tmp_path):
    path = tmp_path / "fresh.sqlite"
    db.init_db(path)
    columns = {row["name"] for row in rows(path, "PRAGMA table_info(apps)")}
    assert "category_id" in columns and "category" not in columns
    assert rows(path, "SELECT name FROM categories")[0]["name"] == "Autres"
