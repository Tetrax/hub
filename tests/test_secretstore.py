"""Stockage des secrets email : fichiers dédiés, permissions, priorité, pièges.

Ces tests portent sur `app/secretstore.py` : écriture atomique en 0600, lecture
défensive (jamais de suivi de lien, jamais d'exception), priorité
administration > environnement, et validation des valeurs.
"""

from __future__ import annotations

import os
import stat

import pytest

from app import secretstore

NAME = secretstore.SMTP_PASSWORD
SECRET = "mot-de-passe-smtp-tres-secret"


def test_write_then_read_round_trip(tmp_path):
    secretstore.write_secret(tmp_path, NAME, SECRET)
    assert secretstore.read_secret(tmp_path, NAME) == SECRET
    path = secretstore.secret_path(tmp_path, NAME)
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(secretstore.secrets_dir(tmp_path).stat().st_mode) == 0o700


def test_replacing_a_secret_changes_the_value(tmp_path):
    secretstore.write_secret(tmp_path, NAME, "premier")
    secretstore.write_secret(tmp_path, NAME, "second")
    assert secretstore.read_secret(tmp_path, NAME) == "second"


def test_delete_removes_the_secret_and_reports_presence(tmp_path):
    secretstore.write_secret(tmp_path, NAME, SECRET)
    assert secretstore.delete_secret(tmp_path, NAME) is True
    assert secretstore.read_secret(tmp_path, NAME) == ""
    assert secretstore.delete_secret(tmp_path, NAME) is False


def test_effective_secret_prefers_the_admin_secret(tmp_path):
    secretstore.write_secret(tmp_path, NAME, "administre")
    value, source = secretstore.effective_secret(tmp_path, NAME, "environnement")
    assert (value, source) == ("administre", secretstore.SOURCE_ADMIN)


def test_environment_is_used_only_without_an_admin_secret(tmp_path):
    value, source = secretstore.effective_secret(tmp_path, NAME, "environnement")
    assert (value, source) == ("environnement", secretstore.SOURCE_ENV)
    secretstore.write_secret(tmp_path, NAME, "administre")
    secretstore.delete_secret(tmp_path, NAME)
    assert secretstore.effective_secret(tmp_path, NAME, "environnement") == (
        "environnement",
        secretstore.SOURCE_ENV,
    )


def test_nothing_configured_reports_no_source(tmp_path):
    assert secretstore.effective_secret(tmp_path, NAME, "") == ("", "")
    assert secretstore.status(tmp_path, NAME, "") == ""


@pytest.mark.parametrize("value", ["", "   ", "\n\t", "x" * (secretstore.MAX_SECRET_BYTES + 1)])
def test_invalid_values_are_refused(tmp_path, value):
    with pytest.raises(secretstore.SecretValidationError):
        secretstore.write_secret(tmp_path, NAME, value)
    assert not secretstore.secret_path(tmp_path, NAME).exists()


def test_a_symlinked_target_is_refused(tmp_path):
    secretstore.ensure_dir(tmp_path)
    elsewhere = tmp_path / "ailleurs.txt"
    elsewhere.write_text("intact", encoding="utf-8")
    os.symlink(elsewhere, secretstore.secret_path(tmp_path, NAME))
    with pytest.raises(OSError):
        secretstore.write_secret(tmp_path, NAME, SECRET)
    assert elsewhere.read_text(encoding="utf-8") == "intact"


def test_reading_never_follows_a_symlink(tmp_path):
    secretstore.ensure_dir(tmp_path)
    elsewhere = tmp_path / "ailleurs.txt"
    elsewhere.write_text(SECRET, encoding="utf-8")
    os.symlink(elsewhere, secretstore.secret_path(tmp_path, NAME))
    assert secretstore.read_secret(tmp_path, NAME) == ""


def test_unreadable_or_corrupt_files_report_no_secret(tmp_path):
    secretstore.ensure_dir(tmp_path)
    path = secretstore.secret_path(tmp_path, NAME)
    path.write_bytes(b"\xff\xfe\x00binaire")
    assert secretstore.read_secret(tmp_path, NAME) == ""
    path.write_bytes(b"x" * (secretstore.MAX_SECRET_BYTES + 1))
    assert secretstore.read_secret(tmp_path, NAME) == ""


def test_no_temporary_file_survives_a_write(tmp_path):
    secretstore.write_secret(tmp_path, NAME, SECRET)
    leftovers = [item.name for item in secretstore.secrets_dir(tmp_path).iterdir() if item.name.startswith(".")]
    assert leftovers == []


def test_unknown_secret_names_are_refused(tmp_path):
    with pytest.raises(ValueError):
        secretstore.secret_path(tmp_path, "inconnu")
    assert secretstore.read_secret(tmp_path, "inconnu") == ""
    assert secretstore.delete_secret(tmp_path, "inconnu") is False


def test_the_secrets_dir_permissions_are_tightened(tmp_path):
    directory = secretstore.secrets_dir(tmp_path)
    directory.mkdir(mode=0o755)
    os.chmod(directory, 0o755)
    secretstore.ensure_dir(tmp_path)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


def test_a_secret_with_trailing_newline_is_read_without_it(tmp_path):
    secretstore.ensure_dir(tmp_path)
    secretstore.secret_path(tmp_path, NAME).write_bytes(b"valeur\n")
    assert secretstore.read_secret(tmp_path, NAME) == "valeur"


@pytest.mark.parametrize("name", secretstore.SECRET_NAMES)
def test_every_managed_secret_round_trips(tmp_path, name):
    """Tous les secrets gérés (SMTP, Microsoft 365, jeton GitHub) suivent le même chemin."""
    secretstore.write_secret(tmp_path, name, f"valeur-{name}")
    assert secretstore.read_secret(tmp_path, name) == f"valeur-{name}"
    assert secretstore.delete_secret(tmp_path, name) is True
    assert secretstore.read_secret(tmp_path, name) == ""


def test_the_github_token_is_a_managed_secret(tmp_path):
    assert secretstore.GITHUB_TOKEN == "github-token"
    assert secretstore.GITHUB_TOKEN in secretstore.SECRET_NAMES
    secretstore.write_secret(tmp_path, secretstore.GITHUB_TOKEN, "jeton-github")
    assert secretstore.effective_secret(tmp_path, secretstore.GITHUB_TOKEN, "env") == (
        "jeton-github",
        secretstore.SOURCE_ADMIN,
    )
