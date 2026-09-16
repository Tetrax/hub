"""Accès au catalogue : applications, catégories administrables, ordre, statistiques."""

from __future__ import annotations

import sqlite3

from . import db
from .urls import validate_category_name

POSITION_STEP = 10

_APP_SELECT = (
    "SELECT a.*, c.name AS category_name, c.slug AS category_slug "
    "FROM apps a LEFT JOIN categories c ON c.id = a.category_id"
)


# --- Applications ------------------------------------------------------------


def list_apps(
    connection: sqlite3.Connection,
    *,
    enabled_only: bool = False,
    category_slug: str | None = None,
    query: str | None = None,
) -> list[sqlite3.Row]:
    clauses = []
    params: list[object] = []
    if enabled_only:
        clauses.append("a.enabled = 1")
    if category_slug:
        clauses.append("c.slug = ?")
        params.append(category_slug)
    if query:
        clauses.append("(a.name LIKE ? OR a.description LIKE ?)")
        like = f"%{query}%"
        params.extend([like, like])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return list(
        connection.execute(
            f"{_APP_SELECT} {where} ORDER BY a.position ASC, a.name COLLATE NOCASE ASC",
            params,
        )
    )


def get_app(connection: sqlite3.Connection, app_id: int) -> sqlite3.Row | None:
    return connection.execute(f"{_APP_SELECT} WHERE a.id = ?", (app_id,)).fetchone()


def next_position(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT MAX(position) AS max_position FROM apps").fetchone()
    return (row["max_position"] or 0) + POSITION_STEP


def slug_exists(connection: sqlite3.Connection, slug: str, exclude_id: int | None = None) -> bool:
    if exclude_id is None:
        row = connection.execute("SELECT 1 FROM apps WHERE slug = ?", (slug,)).fetchone()
    else:
        row = connection.execute(
            "SELECT 1 FROM apps WHERE slug = ? AND id != ?", (slug, exclude_id)
        ).fetchone()
    return row is not None


def create_app(connection: sqlite3.Connection, data: dict) -> tuple[int | None, str | None]:
    if slug_exists(connection, data["slug"]):
        return None, f"Le slug « {data['slug']} » est déjà utilisé."
    if get_category(connection, data["category_id"]) is None:
        return None, "Catégorie inconnue."
    now = db.now_iso()
    cursor = connection.execute(
        "INSERT INTO apps (slug, name, description, url, image, category_id, position, enabled, "
        "status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
        (
            data["slug"],
            data["name"],
            data.get("description", ""),
            data["url"],
            data.get("image"),
            data["category_id"],
            data.get("position") or next_position(connection),
            data.get("status", "production"),
            now,
            now,
        ),
    )
    connection.commit()
    new_id = cursor.lastrowid
    if new_id is None:
        return None, "Création impossible : identifiant non attribué."
    return int(new_id), None


def update_app(
    connection: sqlite3.Connection, app_id: int, data: dict
) -> tuple[bool, str | None]:
    if slug_exists(connection, data["slug"], exclude_id=app_id):
        return False, f"Le slug « {data['slug']} » est déjà utilisé."
    if get_category(connection, data["category_id"]) is None:
        return False, "Catégorie inconnue."
    result = connection.execute(
        "UPDATE apps SET slug = ?, name = ?, description = ?, url = ?, category_id = ?, "
        "status = ?, updated_at = ? WHERE id = ?",
        (
            data["slug"],
            data["name"],
            data.get("description", ""),
            data["url"],
            data["category_id"],
            data.get("status", "production"),
            db.now_iso(),
            app_id,
        ),
    )
    connection.commit()
    return result.rowcount > 0, None


def set_image(connection: sqlite3.Connection, app_id: int, filename: str | None) -> None:
    connection.execute(
        "UPDATE apps SET image = ?, updated_at = ? WHERE id = ?",
        (filename, db.now_iso(), app_id),
    )
    connection.commit()


def delete_app(connection: sqlite3.Connection, app_id: int) -> bool:
    result = connection.execute("DELETE FROM apps WHERE id = ?", (app_id,))
    connection.commit()
    return result.rowcount > 0


def toggle_app(connection: sqlite3.Connection, app_id: int) -> bool | None:
    row = get_app(connection, app_id)
    if row is None:
        return None
    connection.execute(
        "UPDATE apps SET enabled = ?, updated_at = ? WHERE id = ?",
        (0 if row["enabled"] else 1, db.now_iso(), app_id),
    )
    connection.commit()
    return bool(not row["enabled"])


def normalize_positions(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        "SELECT id FROM apps ORDER BY position ASC, name COLLATE NOCASE ASC"
    ).fetchall()
    for index, row in enumerate(rows):
        connection.execute(
            "UPDATE apps SET position = ? WHERE id = ?", ((index + 1) * POSITION_STEP, row["id"])
        )
    connection.commit()


def move_app(connection: sqlite3.Connection, app_id: int, direction: str) -> bool:
    rows = connection.execute(
        "SELECT id FROM apps ORDER BY position ASC, name COLLATE NOCASE ASC"
    ).fetchall()
    ids = [row["id"] for row in rows]
    if app_id not in ids:
        return False
    index = ids.index(app_id)
    if direction == "up" and index > 0:
        ids[index - 1], ids[index] = ids[index], ids[index - 1]
    elif direction == "down" and index < len(ids) - 1:
        ids[index + 1], ids[index] = ids[index], ids[index + 1]
    else:
        return False
    for new_index, current_id in enumerate(ids):
        connection.execute(
            "UPDATE apps SET position = ? WHERE id = ?", ((new_index + 1) * POSITION_STEP, current_id)
        )
    connection.commit()
    return True


def stats(connection: sqlite3.Connection) -> dict:
    row = connection.execute(
        "SELECT COUNT(*) AS total, SUM(enabled) AS enabled FROM apps"
    ).fetchone()
    total = row["total"] or 0
    enabled = int(row["enabled"] or 0)
    return {"total": total, "enabled": enabled, "disabled": total - enabled}


# --- Catégories --------------------------------------------------------------


def list_categories(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    """Toutes les catégories, avec leur nombre d'applications (toutes visibilités)."""
    return list(
        connection.execute(
            "SELECT c.*, (SELECT COUNT(*) FROM apps a WHERE a.category_id = c.id) AS usage_count "
            "FROM categories c ORDER BY c.position ASC, c.name COLLATE NOCASE ASC"
        )
    )


def public_categories(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    """Catégories utilisées par au moins une application affichée sur le portail."""
    return list(
        connection.execute(
            "SELECT c.id, c.name, c.slug, "
            "(SELECT COUNT(*) FROM apps a WHERE a.category_id = c.id AND a.enabled = 1) "
            "AS usage_count "
            "FROM categories c "
            "WHERE EXISTS (SELECT 1 FROM apps a WHERE a.category_id = c.id AND a.enabled = 1) "
            "ORDER BY c.position ASC, c.name COLLATE NOCASE ASC"
        )
    )


def get_category(connection: sqlite3.Connection, category_id: int) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT * FROM categories WHERE id = ?", (category_id,)
    ).fetchone()


def get_category_by_slug(connection: sqlite3.Connection, slug: str) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT * FROM categories WHERE slug = ?", (slug,)
    ).fetchone()


def get_fallback_category(connection: sqlite3.Connection) -> sqlite3.Row | None:
    row = connection.execute("SELECT * FROM categories WHERE is_fallback = 1").fetchone()
    if row is not None:
        return row
    return get_category_by_slug(connection, db.FALLBACK_CATEGORY_SLUG)


def category_name_exists(
    connection: sqlite3.Connection, name: str, exclude_id: int | None = None
) -> bool:
    if exclude_id is None:
        row = connection.execute(
            "SELECT 1 FROM categories WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
    else:
        row = connection.execute(
            "SELECT 1 FROM categories WHERE name = ? COLLATE NOCASE AND id != ?",
            (name, exclude_id),
        ).fetchone()
    return row is not None


def count_apps_in_category(connection: sqlite3.Connection, category_id: int) -> int:
    row = connection.execute(
        "SELECT COUNT(*) AS total FROM apps WHERE category_id = ?", (category_id,)
    ).fetchone()
    return int(row["total"] or 0)


def apps_in_category(connection: sqlite3.Connection, category_id: int) -> list[sqlite3.Row]:
    return list(
        connection.execute(
            f"{_APP_SELECT} WHERE a.category_id = ? "
            "ORDER BY a.position ASC, a.name COLLATE NOCASE ASC",
            (category_id,),
        )
    )


def next_category_position(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT MAX(position) AS max_position FROM categories").fetchone()
    return (row["max_position"] or 0) + POSITION_STEP


def create_category(
    connection: sqlite3.Connection, name: str
) -> tuple[sqlite3.Row | None, str | None]:
    clean_name, error = validate_category_name(name)
    if error:
        return None, error
    if category_name_exists(connection, clean_name):
        return None, f"La catégorie « {clean_name} » existe déjà."
    now = db.now_iso()
    cursor = connection.execute(
        "INSERT INTO categories (name, slug, position, is_fallback, created_at, updated_at) "
        "VALUES (?, ?, ?, 0, ?, ?)",
        (
            clean_name,
            db.unique_category_slug(connection, clean_name),
            next_category_position(connection),
            now,
            now,
        ),
    )
    connection.commit()
    new_id = cursor.lastrowid
    if new_id is None:
        return None, "Création impossible : identifiant non attribué."
    return get_category(connection, int(new_id)), None


def rename_category(
    connection: sqlite3.Connection, category_id: int, name: str
) -> tuple[bool, str | None]:
    row = get_category(connection, category_id)
    if row is None:
        return False, "Catégorie introuvable."
    if row["is_fallback"]:
        return False, "La catégorie de repli ne peut pas être renommée."
    clean_name, error = validate_category_name(name)
    if error:
        return False, error
    if category_name_exists(connection, clean_name, exclude_id=category_id):
        return False, f"La catégorie « {clean_name} » existe déjà."
    connection.execute(
        "UPDATE categories SET name = ?, updated_at = ? WHERE id = ?",
        (clean_name, db.now_iso(), category_id),
    )
    connection.commit()
    return True, None


def move_category(connection: sqlite3.Connection, category_id: int, direction: str) -> bool:
    rows = connection.execute(
        "SELECT id FROM categories ORDER BY position ASC, name COLLATE NOCASE ASC"
    ).fetchall()
    ids = [row["id"] for row in rows]
    if category_id not in ids:
        return False
    index = ids.index(category_id)
    if direction == "up" and index > 0:
        ids[index - 1], ids[index] = ids[index], ids[index - 1]
    elif direction == "down" and index < len(ids) - 1:
        ids[index + 1], ids[index] = ids[index], ids[index + 1]
    else:
        return False
    for new_index, current_id in enumerate(ids):
        connection.execute(
            "UPDATE categories SET position = ? WHERE id = ?",
            ((new_index + 1) * POSITION_STEP, current_id),
        )
    connection.commit()
    return True


def delete_category(
    connection: sqlite3.Connection,
    category_id: int,
    reassign_to: int | None = None,
) -> tuple[bool, str | None, int]:
    """Supprime une catégorie ; réassigne ses applications si demandé.

    Retourne (succès, erreur, nombre d'applications réassignées). La catégorie de
    repli (« Autres ») ne peut pas être supprimée : elle garantit qu'aucune
    application ne se retrouve sans catégorie.
    """
    row = get_category(connection, category_id)
    if row is None:
        return False, "Catégorie introuvable.", 0
    if row["is_fallback"]:
        return False, "La catégorie de repli ne peut pas être supprimée.", 0
    used = count_apps_in_category(connection, category_id)
    reassigned = 0
    if used:
        if reassign_to is None:
            return False, "Cette catégorie est utilisée : choisissez une catégorie de destination.", 0
        if reassign_to == category_id:
            return False, "La catégorie de destination doit être différente.", 0
        target = get_category(connection, reassign_to)
        if target is None:
            return False, "Catégorie de destination introuvable.", 0
        now = db.now_iso()
        connection.execute(
            "UPDATE apps SET category_id = ?, updated_at = ? WHERE category_id = ?",
            (reassign_to, now, category_id),
        )
        reassigned = used
    connection.execute("DELETE FROM categories WHERE id = ?", (category_id,))
    connection.commit()
    return True, None, reassigned
