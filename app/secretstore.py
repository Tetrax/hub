"""Stockage dédié des secrets administrables (email + jeton GitHub).

Les secrets ne sont **jamais** des paramètres ordinaires : ils ne vivent ni en
base, ni dans une réponse HTTP, ni dans un log. Chaque secret est un fichier du
répertoire de données (`secrets/`, 0700, fichier 0600), écrit de façon atomique
par l'administration, relu en mémoire uniquement au moment de l'usage.

Secrets gérés : mot de passe SMTP, secret client Microsoft 365, jeton GitHub
(lecture seule, portée `Actions: Read`).

Priorité (source de vérité) :

1. le secret enregistré depuis l'administration est prioritaire dès qu'il existe ;
2. la variable d'environnement (`HUB_SMTP_PASSWORD`, `HUB_MICROSOFT_CLIENT_SECRET`,
   `HUB_GITHUB_TOKEN`) ne sert que de bootstrap — elle n'est utilisée que tant
   qu'aucun secret administré n'existe. Supprimer un secret administré ré-expose
   la valeur du déploiement, ce que l'UI indique explicitement (provenance).

Les écritures sont atomiques (fichier temporaire + `os.replace`), refusent de
suivre un lien symbolique, et le répertoire est créé en 0700. Aucune fonction de
ce module ne journalise ni ne renvoie un secret : `read_secret` retourne une
chaîne vide en cas d'absence ou d'illisibilité.
"""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

SMTP_PASSWORD = "smtp-password"
MICROSOFT365_CLIENT_SECRET = "microsoft365-client-secret"
GITHUB_TOKEN = "github-token"
SECRET_NAMES = (SMTP_PASSWORD, MICROSOFT365_CLIENT_SECRET, GITHUB_TOKEN)
SECRETS_DIRNAME = "secrets"
MAX_SECRET_BYTES = 4096

# Provenance effective d'un secret (affichée dans l'administration).
SOURCE_ADMIN = "admin"
SOURCE_ENV = "env"


class SecretValidationError(ValueError):
    """Valeur de secret vide, blanche ou hors bornes."""


def validate_secret(value: object) -> bytes:
    """Valeur exploitable : non vide, non blanche, ≤ 4096 octets UTF-8."""
    if not isinstance(value, str) or not value:
        raise SecretValidationError("Secret invalide.")
    if not value.strip():
        raise SecretValidationError("Secret invalide.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise SecretValidationError("Secret invalide.") from error
    if len(encoded) > MAX_SECRET_BYTES:
        raise SecretValidationError("Secret invalide.")
    return encoded


def secrets_dir(data_dir: Path | str) -> Path:
    return Path(data_dir) / SECRETS_DIRNAME


def secret_path(data_dir: Path | str, name: str) -> Path:
    if name not in SECRET_NAMES:
        raise ValueError("Secret inconnu.")
    return secrets_dir(data_dir) / name


def _open_dir(path: Path) -> int:
    """Ouvre un répertoire par descripteur, sans suivre de lien symbolique."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    return os.open(path, flags)


def ensure_dir(data_dir: Path | str) -> Path:
    """Crée le répertoire des secrets (0700) ; refuse un lien symbolique."""
    directory = secrets_dir(data_dir)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink():
        raise OSError("Répertoire des secrets invalide.")
    os.chmod(directory, 0o700)
    return directory


def _entry_is_symlink(directory_fd: int, name: str) -> bool:
    try:
        return stat.S_ISLNK(os.lstat(name, dir_fd=directory_fd).st_mode)
    except OSError:
        return False


def read_secret(data_dir: Path | str, name: str) -> str:
    """Lit un secret ; absent, illisible ou invalide → chaîne vide (jamais d'exception)."""
    try:
        path = secret_path(data_dir, name)
    except ValueError:
        return ""
    try:
        directory_fd = _open_dir(path.parent)
    except OSError:
        return ""
    descriptor = -1
    raw = b""
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return ""
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(MAX_SECRET_BYTES + 1)
    except OSError:
        return ""
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except OSError:
                pass
        os.close(directory_fd)
    if len(raw) > MAX_SECRET_BYTES:
        return ""
    try:
        return raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError:
        return ""


def write_secret(data_dir: Path | str, name: str, value: object) -> None:
    """Écrit un secret de façon atomique (0600). Lève ValueError / OSError."""
    encoded = validate_secret(value)
    path = secret_path(data_dir, name)
    ensure_dir(data_dir)
    directory_fd = _open_dir(path.parent)
    temporary_name = ""
    try:
        if _entry_is_symlink(directory_fd, path.name):
            raise OSError("Cible de secret invalide.")
        temporary_name = f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                os.fchmod(handle.fileno(), 0o600)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if descriptor != -1:
                os.close(descriptor)
        os.replace(temporary_name, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        temporary_name = ""
        try:
            os.fsync(directory_fd)
        except OSError:
            # Le renommage est déjà atomique ; l'absence de fsync n'invalide rien ici.
            pass
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except OSError:
                pass
        os.close(directory_fd)


def delete_secret(data_dir: Path | str, name: str) -> bool:
    """Supprime le secret administré ; True s'il existait. Jamais d'exception."""
    try:
        path = secret_path(data_dir, name)
    except ValueError:
        return False
    try:
        directory_fd = _open_dir(path.parent)
    except OSError:
        return False
    try:
        os.unlink(path.name, dir_fd=directory_fd)
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
        return True
    except OSError:
        return False
    finally:
        os.close(directory_fd)


def effective_secret(
    data_dir: Path | str, name: str, environment_value: str
) -> tuple[str, str]:
    """Valeur effective et provenance : (`SOURCE_ADMIN` | `SOURCE_ENV` | « »)."""
    stored = read_secret(data_dir, name)
    if stored:
        return stored, SOURCE_ADMIN
    value = (environment_value or "").strip()
    if value:
        return value, SOURCE_ENV
    return "", ""


def status(data_dir: Path | str, name: str, environment_value: str) -> str:
    """Provenance seule, sans exposer la valeur (pour l'administration)."""
    return effective_secret(data_dir, name, environment_value)[1]
