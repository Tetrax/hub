"""Accès SQLite : schéma, migrations, connexions, horodatage UTC.

Une connexion par requête (thread-safe) ; WAL activé pour permettre les lectures
concurrentes pendant une écriture.

Le schéma est versionné par `PRAGMA user_version` :
- version 1 : `apps.category` était un simple texte libre ;
- version 2 : les catégories sont des entités (`categories`) référencées par
  `apps.category_id`. La migration est idempotente et transactionnelle.
"""

from __future__ import annotations

import re
import sqlite3
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 2

FALLBACK_CATEGORY_NAME = "Autres"
FALLBACK_CATEGORY_SLUG = "autres"

SCHEMA = """
CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE COLLATE NOCASE,
    position INTEGER NOT NULL DEFAULT 0,
    is_fallback INTEGER NOT NULL DEFAULT 0 CHECK (is_fallback IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL,
    image TEXT,
    category_id INTEGER NOT NULL REFERENCES categories(id),
    position INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'production'
        CHECK (status IN ('production', 'beta', 'maintenance', 'indisponible')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_apps_category ON apps (category_id);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    password_changed_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
    key TEXT PRIMARY KEY,
    failures INTEGER NOT NULL DEFAULT 0,
    first_at TEXT NOT NULL,
    last_at TEXT NOT NULL,
    locked_until TEXT
);

CREATE TABLE IF NOT EXISTS cert_validations (
    ticket_hash TEXT PRIMARY KEY,
    session_hash TEXT NOT NULL,
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
"""

DEFAULT_SETTINGS = {
    "open_links_new_tab": "1",
}

_APPS_COLUMNS_V2 = (
    "id, slug, name, description, url, image, category_id, position, enabled, "
    "status, created_at, updated_at"
)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def connect(db_path: Path | str) -> sqlite3.Connection:
    connection = sqlite3.connect(str(db_path), timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA synchronous=NORMAL")
    return connection


def init_db(db_path: Path | str) -> None:
    connection = connect(db_path)
    try:
        _migrate_legacy_categories(connection)
        connection.executescript(SCHEMA)
        _ensure_fallback_category(connection)
        for key, value in DEFAULT_SETTINGS.items():
            connection.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value)
            )
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        connection.commit()
    finally:
        connection.close()


def category_slug(name: str) -> str:
    """Slug ASCII stable pour une catégorie (« Sécurité » → « securite »)."""
    ascii_name = (
        unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode("ascii")
    )
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)[:40].strip("-")
    if len(slug) < 2:
        slug = (slug + "-cat").strip("-")
    return slug


def unique_category_slug(connection: sqlite3.Connection, name: str) -> str:
    base = category_slug(name)
    candidate = base
    suffix = 2
    while connection.execute(
        "SELECT 1 FROM categories WHERE slug = ?", (candidate,)
    ).fetchone():
        candidate = f"{base[:36]}-{suffix}"
        suffix += 1
    return candidate


def _table_exists(connection: sqlite3.Connection, name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone()
    return row is not None


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}


def _migrate_legacy_categories(connection: sqlite3.Connection) -> None:
    """Migration v1 → v2 : `apps.category` (texte) devient `categories` + `apps.category_id`.

    Idempotente (détecte l'ancienne colonne) et transactionnelle : aucune
    application, aucune catégorie et aucune association ne peut être perdue.
    """
    if not _table_exists(connection, "apps") or "category" not in _columns(connection, "apps"):
        return

    now = now_iso()
    connection.isolation_level = None  # transaction explicite (DDL + DML atomiques)
    try:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("BEGIN IMMEDIATE")

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                slug TEXT NOT NULL UNIQUE COLLATE NOCASE,
                position INTEGER NOT NULL DEFAULT 0,
                is_fallback INTEGER NOT NULL DEFAULT 0 CHECK (is_fallback IN (0, 1)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        def insert_category(name: str, position: int, is_fallback: int) -> int:
            slug = category_slug(name)
            candidate, suffix = slug, 2
            while connection.execute(
                "SELECT 1 FROM categories WHERE slug = ?", (candidate,)
            ).fetchone():
                candidate = f"{slug[:36]}-{suffix}"
                suffix += 1
            cursor = connection.execute(
                "INSERT INTO categories (name, slug, position, is_fallback, created_at, "
                "updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (name, candidate, position, is_fallback, now, now),
            )
            new_id = cursor.lastrowid
            if new_id is None:
                raise RuntimeError("Migration des catégories : identifiant non attribué.")
            return int(new_id)

        fallback_id = insert_category(FALLBACK_CATEGORY_NAME, 0, 1)
        legacy_names = [
            row["category"]
            for row in connection.execute(
                "SELECT TRIM(COALESCE(category, '')) COLLATE NOCASE AS category, "
                "MIN(position) AS first_position FROM apps "
                "WHERE TRIM(COALESCE(category, '')) != '' "
                "GROUP BY category COLLATE NOCASE "
                "ORDER BY first_position ASC, category COLLATE NOCASE ASC"
            )
        ]
        mapping: dict[str, int] = {}
        for index, name in enumerate(legacy_names):
            key = name.casefold()
            if key in mapping:
                continue
            if key == FALLBACK_CATEGORY_NAME.casefold():
                mapping[key] = fallback_id
                continue
            mapping[key] = insert_category(name, (index + 1) * 10, 0)

        connection.execute(
            """
            CREATE TABLE apps_v2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slug TEXT NOT NULL UNIQUE COLLATE NOCASE,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                url TEXT NOT NULL,
                image TEXT,
                category_id INTEGER NOT NULL REFERENCES categories(id),
                position INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'production'
                    CHECK (status IN ('production', 'beta', 'maintenance', 'indisponible')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        for row in connection.execute(
            f"SELECT {_APPS_COLUMNS_V2.replace('category_id, ', '')}, "
            "TRIM(COALESCE(category, '')) AS legacy_category FROM apps"
        ).fetchall():
            category_id = mapping.get(row["legacy_category"].casefold(), fallback_id)
            connection.execute(
                f"INSERT INTO apps_v2 ({_APPS_COLUMNS_V2}) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    row["id"],
                    row["slug"],
                    row["name"],
                    row["description"],
                    row["url"],
                    row["image"],
                    category_id,
                    row["position"],
                    row["enabled"],
                    row["status"],
                    row["created_at"],
                    row["updated_at"],
                ),
            )
        connection.execute("DROP TABLE apps")
        connection.execute("ALTER TABLE apps_v2 RENAME TO apps")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_apps_category ON apps (category_id)")

        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError(f"Migration des catégories : intégrité référentielle ({violations})")

        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    finally:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.isolation_level = "DEFERRED"


def _ensure_fallback_category(connection: sqlite3.Connection) -> None:
    row = connection.execute(
        "SELECT id FROM categories WHERE is_fallback = 1"
    ).fetchone()
    if row is not None:
        return
    now = now_iso()
    slug = FALLBACK_CATEGORY_SLUG
    if connection.execute("SELECT 1 FROM categories WHERE slug = ?", (slug,)).fetchone():
        connection.execute(
            "UPDATE categories SET is_fallback = 1 WHERE slug = ?", (slug,)
        )
        return
    position_row = connection.execute(
        "SELECT COALESCE(MAX(position), 0) AS max_position FROM categories"
    ).fetchone()
    connection.execute(
        "INSERT INTO categories (name, slug, position, is_fallback, created_at, updated_at) "
        "VALUES (?, ?, ?, 1, ?, ?)",
        (FALLBACK_CATEGORY_NAME, slug, (position_row["max_position"] or 0) + 10, now, now),
    )


def get_setting(connection: sqlite3.Connection, key: str, default: str = "") -> str:
    row = connection.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row is not None else default


def set_setting(connection: sqlite3.Connection, key: str, value: str) -> None:
    connection.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    connection.commit()
