"""Accès au catalogue d'applications (CRUD, ordre, statistiques)."""

from __future__ import annotations

import sqlite3

from . import db

POSITION_STEP = 10


def list_apps(
    connection: sqlite3.Connection,
    *,
    enabled_only: bool = False,
    category: str | None = None,
    query: str | None = None,
) -> list[sqlite3.Row]:
    clauses = []
    params: list[object] = []
    if enabled_only:
        clauses.append("enabled = 1")
    if category:
        clauses.append("category = ?")
        params.append(category)
    if query:
        clauses.append("(name LIKE ? OR description LIKE ?)")
        like = f"%{query}%"
        params.extend([like, like])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return list(
        connection.execute(
            f"SELECT * FROM apps {where} ORDER BY position ASC, name COLLATE NOCASE ASC",
            params,
        )
    )


def get_app(connection: sqlite3.Connection, app_id: int) -> sqlite3.Row | None:
    return connection.execute("SELECT * FROM apps WHERE id = ?", (app_id,)).fetchone()


def categories_in_use(connection: sqlite3.Connection) -> list[str]:
    rows = connection.execute(
        "SELECT DISTINCT category FROM apps WHERE enabled = 1 ORDER BY category COLLATE NOCASE"
    ).fetchall()
    return [row["category"] for row in rows if row["category"]]


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
    now = db.now_iso()
    cursor = connection.execute(
        "INSERT INTO apps (slug, name, description, url, image, category, position, enabled, status, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
        (
            data["slug"],
            data["name"],
            data.get("description", ""),
            data["url"],
            data.get("image"),
            data.get("category", "Autres"),
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
    result = connection.execute(
        "UPDATE apps SET slug = ?, name = ?, description = ?, url = ?, category = ?, status = ?, "
        "updated_at = ? WHERE id = ?",
        (
            data["slug"],
            data["name"],
            data.get("description", ""),
            data["url"],
            data.get("category", "Autres"),
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
