"""Stockage des secrets email : fichiers dédiés, permissions, priorité, pièges.

Ces tests portent sur `app/mailsecrets.py` : écriture atomique en 0600, lecture
défensive (jamais de suivi de lien, jamais d'exception), priorité
administration > environnement, et validation des valeurs.
"""

from __future__ import annotations

import os
import stat

import pytest

from app import mailsecrets

NAME = mailsecrets.SMTP_PASSWORD
SECRET = "mot-de-passe-smtp-tres-secret"


def test_write_then_read_round_trip(tmp_path):
    mailsecrets.write_secret(tmp_path, NAME, SECRET)
    assert mailsecrets.read_secret(tmp_path, NAME) == SECRET
    path = mailsecrets.secret_path(tmp_path, NAME)
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(mailsecrets.secrets_dir(tmp_path).stat().st_mode) == 0o700


def test_replacing_a_secret_changes_the_value(tmp_path):
    mailsecrets.write_secret(tmp_path, NAME, "premier")
    mailsecrets.write_secret(tmp_path, NAME, "second")
    assert mailsecrets.read_secret(tmp_path, NAME) == "second"


def test_delete_removes_the_secret_and_reports_presence(tmp_path):
    mailsecrets.write_secret(tmp_path, NAME, SECRET)
    assert mailsecrets.delete_secret(tmp_path, NAME) is True
    assert mailsecrets.read_secret(tmp_path, NAME) == ""
    assert mailsecrets.delete_secret(tmp_path, NAME) is False


def test_effective_secret_prefers_the_admin_secret(tmp_path):
    mailsecrets.write_secret(tmp_path, NAME, "administre")
    value, source = mailsecrets.effective_secret(tmp_path, NAME, "environnement")
    assert (value, source) == ("administre", mailsecrets.SOURCE_ADMIN)


def test_environment_is_used_only_without_an_admin_secret(tmp_path):
    value, source = mailsecrets.effective_secret(tmp_path, NAME, "environnement")
    assert (value, source) == ("environnement", mailsecrets.SOURCE_ENV)
    mailsecrets.write_secret(tmp_path, NAME, "administre")
    mailsecrets.delete_secret(tmp_path, NAME)
    assert mailsecrets.effective_secret(tmp_path, NAME, "environnement") == (
        "environnement",
        mailsecrets.SOURCE_ENV,
    )


def test_nothing_configured_reports_no_source(tmp_path):
    assert mailsecrets.effective_secret(tmp_path, NAME, "") == ("", "")
    assert mailsecrets.status(tmp_path, NAME, "") == ""


@pytest.mark.parametrize("value", ["", "   ", "\n\t", "x" * (mailsecrets.MAX_SECRET_BYTES + 1)])
def test_invalid_values_are_refused(tmp_path, value):
    with pytest.raises(mailsecrets.SecretValidationError):
        mailsecrets.write_secret(tmp_path, NAME, value)
    assert not mailsecrets.secret_path(tmp_path, NAME).exists()


def test_a_symlinked_target_is_refused(tmp_path):
    mailsecrets.ensure_dir(tmp_path)
    elsewhere = tmp_path / "ailleurs.txt"
    elsewhere.write_text("intact", encoding="utf-8")
    os.symlink(elsewhere, mailsecrets.secret_path(tmp_path, NAME))
    with pytest.raises(OSError):
        mailsecrets.write_secret(tmp_path, NAME, SECRET)
    assert elsewhere.read_text(encoding="utf-8") == "intact"


def test_reading_never_follows_a_symlink(tmp_path):
    mailsecrets.ensure_dir(tmp_path)
    elsewhere = tmp_path / "ailleurs.txt"
    elsewhere.write_text(SECRET, encoding="utf-8")
    os.symlink(elsewhere, mailsecrets.secret_path(tmp_path, NAME))
    assert mailsecrets.read_secret(tmp_path, NAME) == ""


def test_unreadable_or_corrupt_files_report_no_secret(tmp_path):
    mailsecrets.ensure_dir(tmp_path)
    path = mailsecrets.secret_path(tmp_path, NAME)
    path.write_bytes(b"\xff\xfe\x00binaire")
    assert mailsecrets.read_secret(tmp_path, NAME) == ""
    path.write_bytes(b"x" * (mailsecrets.MAX_SECRET_BYTES + 1))
    assert mailsecrets.read_secret(tmp_path, NAME) == ""


def test_no_temporary_file_survives_a_write(tmp_path):
    mailsecrets.write_secret(tmp_path, NAME, SECRET)
    leftovers = [item.name for item in mailsecrets.secrets_dir(tmp_path).iterdir() if item.name.startswith(".")]
    assert leftovers == []


def test_unknown_secret_names_are_refused(tmp_path):
    with pytest.raises(ValueError):
        mailsecrets.secret_path(tmp_path, "inconnu")
    assert mailsecrets.read_secret(tmp_path, "inconnu") == ""
    assert mailsecrets.delete_secret(tmp_path, "inconnu") is False


def test_the_secrets_dir_permissions_are_tightened(tmp_path):
    directory = mailsecrets.secrets_dir(tmp_path)
    directory.mkdir(mode=0o755)
    os.chmod(directory, 0o755)
    mailsecrets.ensure_dir(tmp_path)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


def test_a_secret_with_trailing_newline_is_read_without_it(tmp_path):
    mailsecrets.ensure_dir(tmp_path)
    mailsecrets.secret_path(tmp_path, NAME).write_bytes(b"valeur\n")
    assert mailsecrets.read_secret(tmp_path, NAME) == "valeur"
