"""Commandes d'exploitation de SNS Hub.

Utilisation (dans le conteneur ou en local) :

    python -m app.manage seed [chemin/catalog.json]   # amorce le catalogue initial
    python -m app.manage reset-admin                  # réinitialise le mot de passe admin
    python -m app.manage report-orphans               # screenshots non référencés
    python -m app.manage set-password                 # équivalent de reset-admin (alias)

Le mot de passe n'est jamais passé en argument : saisie interactive masquée.
"""

from __future__ import annotations

import getpass
import json
import sys
from pathlib import Path

from . import auth, catalog
from .urls import slugify, validate_app_url, validate_category_name, validate_status


def _category_id(connection, raw_name: str) -> tuple[int | None, str | None]:
    """Identifiant de la catégorie du catalogue initial, créée si nécessaire.

    Les catégories sont des entités en base depuis V1.1 : on résout par nom (slug),
    et on crée la catégorie si elle n'existe pas encore.
    """
    name, error = validate_category_name(raw_name or "")
    if error:
        return None, error
    existing = catalog.get_category_by_slug(connection, slugify(name))
    if existing is not None:
        return int(existing["id"]), None
    row, error = catalog.create_category(connection, name)
    if error or row is None:
        return None, error or "Catégorie non créée."
    return int(row["id"]), None


def _seed(argument: str | None) -> int:
    default_path = Path(__file__).resolve().parent.parent / "seeds" / "catalog.json"
    path = Path(argument) if argument else default_path
    if not path.is_file():
        print(f"Fichier de catalogue introuvable : {path}", file=sys.stderr)
        return 1
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = payload.get("apps", [])
    connection = auth.db_connection()
    if catalog.stats(connection)["total"] > 0:
        print("Le catalogue contient déjà des applications ; rien à amorcer.")
        return 0
    created = 0
    for entry in entries:
        url, error = validate_app_url(entry.get("url", ""))
        if error:
            print(f"Entrée ignorée ({entry.get('name')}) : {error}", file=sys.stderr)
            continue
        category_id, error = _category_id(connection, entry.get("category", "Autres"))
        if error or category_id is None:
            print(f"Entrée ignorée ({entry.get('name')}) : {error}", file=sys.stderr)
            continue
        status, error = validate_status(entry.get("status", "production"))
        if error:
            print(f"Entrée ignorée ({entry.get('name')}) : {error}", file=sys.stderr)
            continue
        app_id, error = catalog.create_app(
            connection,
            {
                "slug": entry.get("slug", ""),
                "name": entry.get("name", "").strip(),
                "description": entry.get("description", "").strip(),
                "url": url,
                "category_id": category_id,
                "status": status,
                "position": entry.get("position"),
            },
        )
        if error:
            print(f"Entrée ignorée ({entry.get('name')}) : {error}", file=sys.stderr)
            continue
        created += 1
        print(f"Application ajoutée : {entry.get('name')} (id={app_id})")
    print(f"{created} application(s) ajoutée(s) depuis {path}.")
    return 0


def _reset_admin() -> int:
    connection = auth.db_connection()
    if not auth.has_admin(connection):
        print("Aucun compte administrateur : utilisez la première configuration web (/admin).")
        return 1
    password = getpass.getpass("Nouveau mot de passe administrateur : ")
    confirmation = getpass.getpass("Confirmation : ")
    ok, error = auth.validate_password(password)
    if not ok:
        print(error, file=sys.stderr)
        return 1
    if password != confirmation:
        print("Les deux saisies ne correspondent pas.", file=sys.stderr)
        return 1
    auth.update_password(connection, password)
    auth.destroy_all_sessions(connection)
    print("Mot de passe administrateur réinitialisé ; toutes les sessions ont été invalidées.")
    return 0


def _report_orphans() -> int:
    from flask import current_app

    from .uploads import orphan_files

    connection = auth.db_connection()
    referenced = {
        row["image"] for row in connection.execute("SELECT image FROM apps WHERE image IS NOT NULL")
    }
    orphans = orphan_files(Path(current_app.config["UPLOADS_DIR"]), referenced)
    if not orphans:
        print("Aucun fichier orphelin.")
        return 0
    print(f"{len(orphans)} fichier(s) non référencé(s) :")
    for name in orphans:
        print(f"  {name}")
    print("Suppression : passez --delete (les fichiers listés seront retirés).")
    return 0


def main(argv: list[str]) -> int:
    from . import create_app

    if not argv or argv[0] in {"help", "-h", "--help"}:
        print(__doc__)
        return 0
    command = argv[0]
    app = create_app()
    with app.app_context():
        if command == "seed":
            return _seed(argv[1] if len(argv) > 1 else None)
        if command in {"reset-admin", "set-password"}:
            return _reset_admin()
        if command == "report-orphans":
            return _report_orphans()
    print(f"Commande inconnue : {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
