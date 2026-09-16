"""Screenshots du catalogue : validation du vrai type, nommage sûr, stockage persistant."""

from __future__ import annotations

import os
import re
import uuid
from pathlib import Path

IMAGE_NAME_RE = re.compile(r"^[0-9a-f]{32}\.(png|jpg|webp)$")
EXTENSIONS = {"png": "png", "jpg": "jpg", "webp": "webp"}


def detect_image_type(data: bytes) -> str | None:
    """Type réel par magic bytes — l'extension et le Content-Type déclarés sont ignorés."""
    if len(data) < 12:
        return None
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def is_valid_image_name(name: str) -> bool:
    return bool(name) and bool(IMAGE_NAME_RE.match(name))


def save_screenshot(file_storage, uploads_dir: Path, max_bytes: int) -> tuple[str | None, str | None]:
    """Enregistre le fichier uploadé. Retourne (nom_fichier, erreur)."""
    if file_storage is None or not getattr(file_storage, "filename", ""):
        return None, "Aucun fichier sélectionné."
    data = file_storage.read(max_bytes + 1)
    if not data:
        return None, "Fichier vide."
    if len(data) > max_bytes:
        return None, f"Fichier trop volumineux (maximum {max_bytes // (1024 * 1024)} Mo)."
    kind = detect_image_type(data)
    if kind is None:
        return None, "Format non pris en charge : PNG, JPEG ou WebP uniquement."
    filename = f"{uuid.uuid4().hex}.{EXTENSIONS[kind]}"
    target = Path(uploads_dir) / filename
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return filename, None


def delete_screenshot(uploads_dir: Path, filename: str | None) -> None:
    """Supprime un screenshot du stockage (best effort, nom strictement contrôlé)."""
    if not filename or not is_valid_image_name(filename):
        return
    target = Path(uploads_dir) / filename
    try:
        if target.is_file() and not target.is_symlink():
            target.unlink()
    except OSError:
        pass


def orphan_files(uploads_dir: Path, referenced: set[str]) -> list[str]:
    """Fichiers présents mais non référencés par le catalogue."""
    try:
        return sorted(
            entry.name
            for entry in Path(uploads_dir).iterdir()
            if entry.is_file() and is_valid_image_name(entry.name) and entry.name not in referenced
        )
    except FileNotFoundError:
        return []
