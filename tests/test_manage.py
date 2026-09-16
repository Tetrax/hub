"""Commandes d'exploitation `python -m app.manage`.

Ces commandes sont documentées (AGENTS.md, docs/operations.md) et servent
notamment à amorcer un catalogue sur une installation neuve : elles doivent
rester utilisables. L'import du module a déjà régressé silencieusement lors de la
migration des catégories (V1.1) — ces tests verrouillent le chemin réel, c'est-à
-dire `python -m app.manage <commande>` sur un répertoire de données vierge.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from app import auth, manage

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture()
def cli_data(tmp_path, monkeypatch):
    """Répertoire de données vierge utilisé par les commandes (`create_app`)."""
    data = tmp_path / "cli-data"
    data.mkdir()
    monkeypatch.setenv("HUB_DATA_DIR", str(data))
    return data


def db(data: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(data / "hub.sqlite")
    connection.row_factory = sqlite3.Row
    return connection


def write_catalog(path: Path, entries: list[dict]) -> Path:
    path.write_text(json.dumps({"apps": entries}, ensure_ascii=False), encoding="utf-8")
    return path


def sample_entries() -> list[dict]:
    return [
        {
            "slug": "alpha",
            "name": "Alpha",
            "description": "Première application",
            "url": "https://alpha.intra.example",
            "category": "Fortinet",
            "status": "production",
            "position": 10,
        },
        {
            "slug": "beta",
            "name": "Beta",
            "description": "Deuxième application",
            "url": "https://beta.intra.example",
            "category": "Sécurité",
            "status": "production",
            "position": 20,
        },
        {
            "slug": "invalide",
            "name": "Invalide",
            "description": "URL refusée",
            "url": "ftp://interdit.example",
            "category": "Fortinet",
            "status": "production",
        },
    ]


# --- Module -------------------------------------------------------------------


def test_all_documented_commands_are_declared():
    """Aucun import cassé : le module se charge et annonce ses commandes."""
    description = manage.__doc__ or ""
    for command in ("seed", "reset-admin", "report-orphans"):
        assert command in description


def test_unknown_command_returns_error_code(cli_data, capsys):
    assert manage.main(["inconnue"]) == 2
    assert "Commande inconnue" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["help", "-h", "--help"])
def test_help_prints_usage(cli_data, command, capsys):
    assert manage.main([command]) == 0
    assert "seed" in capsys.readouterr().out


# --- seed ---------------------------------------------------------------------


def test_seed_creates_apps_and_categories(cli_data, tmp_path, capsys):
    path = write_catalog(tmp_path / "catalog.json", sample_entries())
    assert manage.main(["seed", str(path)]) == 0

    connection = db(cli_data)
    names = [row["name"] for row in connection.execute("SELECT name FROM apps ORDER BY position")]
    categories = {row["name"] for row in connection.execute("SELECT name FROM categories")}
    rows = list(
        connection.execute(
            "SELECT a.name, c.name AS category, c.is_fallback FROM apps a "
            "JOIN categories c ON c.id = a.category_id ORDER BY a.position"
        )
    )
    assert names == ["Alpha", "Beta"]  # l'entrée invalide est ignorée (journalisée)
    assert {"Fortinet", "Sécurité"} <= categories
    assert [(row["name"], row["category"]) for row in rows] == [
        ("Alpha", "Fortinet"),
        ("Beta", "Sécurité"),
    ]
    assert all(row["is_fallback"] == 0 for row in rows)
    assert "2 application(s) ajoutée(s)" in capsys.readouterr().out


def test_seed_is_idempotent_and_creates_no_duplicate_category(cli_data, tmp_path, capsys):
    path = write_catalog(tmp_path / "catalog.json", sample_entries())
    assert manage.main(["seed", str(path)]) == 0
    assert manage.main(["seed", str(path)]) == 0
    output = capsys.readouterr().out
    assert "contient déjà des applications" in output

    connection = db(cli_data)
    assert connection.execute("SELECT COUNT(*) FROM apps").fetchone()[0] == 2
    assert connection.execute("SELECT COUNT(*) FROM categories").fetchone()[0] == 3


def test_seed_ignores_missing_file(cli_data, capsys):
    assert manage.main(["seed", "/inexistant/catalog.json"]) == 1
    assert "introuvable" in capsys.readouterr().err


def test_shipped_seed_catalog_is_valid_and_loads(cli_data, capsys):
    """Le catalogue livré (`seeds/catalog.json`) doit rester importable tel quel."""
    payload = json.loads((REPO / "seeds" / "catalog.json").read_text(encoding="utf-8"))
    entries = payload.get("apps") or []
    assert entries
    for entry in entries:
        assert entry.get("slug") and entry.get("name") and entry.get("url")
        assert entry.get("category") and entry.get("status")

    assert manage.main(["seed"]) == 0
    assert "application(s) ajoutée(s)" in capsys.readouterr().out
    connection = db(cli_data)
    assert connection.execute("SELECT COUNT(*) FROM apps").fetchone()[0] == len(entries)
    assert connection.execute("SELECT COUNT(*) FROM apps WHERE category_id IS NULL").fetchone()[0] == 0


# --- report-orphans -----------------------------------------------------------


def test_report_orphans_lists_unreferenced_files(cli_data, capsys):
    assert manage.main(["seed"]) == 0
    uploads = cli_data / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    orphan = uploads / "0123456789abcdef0123456789abcdef.webp"
    orphan.write_bytes(b"RIFF0000WEBP")

    assert manage.main(["report-orphans"]) == 0
    output = capsys.readouterr().out
    assert orphan.name in output
    assert orphan.exists()  # aucun effacement implicite


def test_report_orphans_without_orphan(cli_data, capsys):
    assert manage.main(["seed"]) == 0
    assert manage.main(["report-orphans"]) == 0
    assert "Aucun fichier orphelin" in capsys.readouterr().out


# --- reset-admin --------------------------------------------------------------


def create_cli_admin(data: Path, username: str = "admin", password: str = "MotDePasse-Admin-1"):
    """Compte administrateur créé directement dans la base utilisée par la CLI."""
    assert manage.main(["seed"]) == 0
    connection = sqlite3.connect(data / "hub.sqlite")
    connection.row_factory = sqlite3.Row
    assert auth.create_admin(connection, username, password)
    connection.close()


def test_reset_admin_requires_an_existing_account(cli_data, capsys):
    assert manage.main(["seed"]) == 0
    assert manage.main(["reset-admin"]) == 1
    assert "Aucun compte administrateur" in capsys.readouterr().out


def test_reset_admin_updates_password_and_invalidates_sessions(cli_data, monkeypatch):
    from app import create_app

    create_cli_admin(cli_data)
    connection = db(cli_data)
    username = auth.admin_username(connection) or "admin"
    with create_app().app_context():  # create_session lit la configuration de session
        auth.create_session(connection, username)
    connection.commit()
    assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    connection.close()

    answers = iter(["Nouveau-MotDePasse-Solide-1", "Nouveau-MotDePasse-Solide-1"])
    monkeypatch.setattr(manage.getpass, "getpass", lambda *_: next(answers))
    assert manage.main(["reset-admin"]) == 0

    connection = db(cli_data)
    assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert auth.verify_admin(connection, username, "Nouveau-MotDePasse-Solide-1")
    connection.close()


def test_reset_admin_refuses_mismatched_confirmation(cli_data, monkeypatch, capsys):
    create_cli_admin(cli_data)
    answers = iter(["Nouveau-MotDePasse-Solide-1", "Autre-Chose-Solide-2"])
    monkeypatch.setattr(manage.getpass, "getpass", lambda *_: next(answers))
    assert manage.main(["reset-admin"]) == 1
    assert "ne correspondent pas" in capsys.readouterr().err

    connection = db(cli_data)
    assert auth.verify_admin(connection, "admin", "MotDePasse-Admin-1")
    connection.close()


def test_set_password_is_an_alias(cli_data, monkeypatch):
    create_cli_admin(cli_data)
    answers = iter(["Encore-Un-MotDePasse-3", "Encore-Un-MotDePasse-3"])
    monkeypatch.setattr(manage.getpass, "getpass", lambda *_: next(answers))
    assert manage.main(["set-password"]) == 0
    connection = db(cli_data)
    assert auth.verify_admin(connection, "admin", "Encore-Un-MotDePasse-3")
    connection.close()
