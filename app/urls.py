"""Validation des entrées : URLs des applications, slugs, catégories, statuts."""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlsplit

ALLOWED_SCHEMES = ("http", "https")
ALLOWED_STATUSES = ("production", "beta", "maintenance", "indisponible")
STATUS_LABELS = {
    "production": "Production",
    "beta": "Bêta",
    "maintenance": "Maintenance",
    "indisponible": "Indisponible",
}

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$")  # 2 à 64 caractères
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def validate_app_url(raw: str) -> tuple[str | None, str | None]:
    """Valide une URL d'application. Retourne (url_normale, erreur)."""
    if not isinstance(raw, str):
        return None, "URL invalide."
    url = raw.strip()
    if not url:
        return None, "L'URL est obligatoire."
    if len(url) > 2048:
        return None, "URL trop longue (2048 caractères maximum)."
    if _CONTROL_RE.search(url) or any(ch.isspace() for ch in url):
        return None, "L'URL ne doit contenir ni espace ni caractère de contrôle."
    try:
        parts = urlsplit(url)
    except ValueError:
        return None, "URL illisible."
    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return None, "Seuls les schémas http:// et https:// sont autorisés."
    if not parts.netloc or not parts.hostname:
        return None, "L'URL doit contenir un nom d'hôte."
    if parts.username or parts.password:
        return None, "L'URL ne doit pas contenir d'identifiants."
    try:
        port = parts.port
    except ValueError:
        return None, "Port invalide dans l'URL."
    if port is not None and not (1 <= port <= 65535):
        return None, "Port invalide dans l'URL."
    return url, None


def slugify(name: str) -> str:
    """Slug ASCII : minuscules, tirets, borné à 48 caractères."""
    ascii_name = (
        unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode("ascii")
    )
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)[:48].strip("-")
    if len(slug) < 2:
        slug = (slug + "-app").strip("-")
    return slug


def validate_slug(raw: str) -> tuple[str | None, str | None]:
    slug = (raw or "").strip().lower()
    if not SLUG_RE.match(slug):
        return None, (
            "Slug invalide : minuscules, chiffres et tirets uniquement "
            "(2 à 64 caractères, sans tiret au début ni à la fin)."
        )
    return slug, None


def validate_name(raw: str) -> tuple[str | None, str | None]:
    name = (raw or "").strip()
    if not name:
        return None, "Le nom est obligatoire."
    if len(name) > 80:
        return None, "Nom trop long (80 caractères maximum)."
    if _CONTROL_RE.search(name):
        return None, "Nom invalide."
    return name, None


def validate_description(raw: str) -> tuple[str, str | None]:
    description = (raw or "").strip()
    if len(description) > 400:
        return "", "Description trop longue (400 caractères maximum)."
    if _CONTROL_RE.search(description.replace("\n", "")):
        return "", "Description invalide."
    return description, None


def validate_category(raw: str) -> tuple[str, str | None]:
    category = (raw or "").strip() or "Autres"
    if len(category) > 40:
        return "", "Catégorie trop longue (40 caractères maximum)."
    if _CONTROL_RE.search(category):
        return "", "Catégorie invalide."
    return category, None


def validate_status(raw: str) -> tuple[str, str | None]:
    status = (raw or "").strip().lower()
    if status not in ALLOWED_STATUSES:
        return "", "Statut invalide."
    return status, None
