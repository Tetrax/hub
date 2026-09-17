"""Configuration de SNS Hub.

Toute la configuration vient de l'environnement (injectée par Compose) ; les
tests surchargent via `create_app(config=...)`. Aucun secret n'est versionné :
la clé de signature est générée et persistée dans le répertoire de données.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

DEFAULT_DATA_DIR = Path("runtime/data")
DEFAULT_CERT_SOCKET = "/run/hub-cert-helper/helper.sock"
DEFAULT_CERTS_DIR = "/certs"

# Libellé de marque affiché dans le header, à côté du logo SNS. Purement visuel :
# aucune conséquence sur le hostname, le certificat, la base ou les sessions.
DEFAULT_BRAND_LABEL = "HUB"
BRAND_LABEL_MAX = 40


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _brand_label(raw: str) -> str:
    """Libellé du header : texte simple (trim, espaces normalisés, sans caractère
    de contrôle), borné en longueur ; jamais de HTML — le gabarit échappe la
    valeur à l'affichage. Une valeur vide ou inexploitable retombe sur le
    libellé générique."""
    value = " ".join((raw or "").split())
    value = "".join(character for character in value if character.isprintable())
    if not value:
        return DEFAULT_BRAND_LABEL
    return value[:BRAND_LABEL_MAX].rstrip() or DEFAULT_BRAND_LABEL


def load_config(base_dir: Path | None = None, overrides: dict | None = None) -> dict:
    """Construit la configuration à partir de l'environnement."""
    base = Path(base_dir) if base_dir is not None else Path.cwd()
    data_dir = Path(os.environ.get("HUB_DATA_DIR", str(base / DEFAULT_DATA_DIR))).resolve()
    config = {
        "DATA_DIR": data_dir,
        "DB_PATH": data_dir / "hub.sqlite",
        "UPLOADS_DIR": data_dir / "uploads",
        "SECRET_KEY_FILE": data_dir / ".secret_key",
        "TLS_HOSTNAME": os.environ.get("HUB_TLS_HOSTNAME", "").strip(),
        "CERT_HELPER_SOCKET": os.environ.get("HUB_CERT_HELPER_SOCKET", DEFAULT_CERT_SOCKET),
        # Backend de gestion des certificats : helper (VPS, défaut), local
        # (standalone : le serveur HTTPS du conteneur est rechargé par SIGHUP),
        # none (TLS assuré en amont par l'infrastructure).
        "CERT_BACKEND": os.environ.get("HUB_CERT_BACKEND", "helper").strip().lower(),
        "CERTS_DIR": os.environ.get("HUB_CERTS_DIR", DEFAULT_CERTS_DIR),
        "TLS_CERT_FILE": os.environ.get("HUB_TLS_CERT", "").strip(),
        "TLS_KEY_FILE": os.environ.get("HUB_TLS_KEY", "").strip(),
        "TLS_BIND_PORT": _env_int("HUB_TLS_BIND_PORT", 8443),
        "GUNICORN_PIDFILE": os.environ.get("HUB_GUNICORN_PIDFILE", "/tmp/gunicorn.pid"),
        "BRAND_LABEL": _brand_label(os.environ.get("HUB_BRAND_LABEL", "")),
        "TRUSTED_PROXY_CIDRS": os.environ.get("HUB_TRUSTED_PROXY_CIDRS", ""),
        "SESSION_TTL_SECONDS": _env_int("HUB_SESSION_TTL_SECONDS", 12 * 3600),
        "GIT_SHA": os.environ.get("HUB_GIT_SHA", "").strip()[:40] or None,
        # Secrets d'infrastructure (V1.6) : fournis par le déploiement, jamais en
        # base, jamais dans Git ni dans une réponse HTTP. Le jeton GitHub est en
        # LECTURE SEULE (portée Actions) : le téléchargement d'artefact l'exige,
        # même pour un dépôt public (vérifié).
        "GITHUB_TOKEN": os.environ.get("HUB_GITHUB_TOKEN", "").strip(),
        # Secrets email (V1.6.1) : **bootstrap uniquement** — la configuration
        # enregistrée dans l'administration (fichiers de `HUB_DATA_DIR/secrets/`)
        # est prioritaire dès qu'elle existe (voir app/secretstore.py).
        "SMTP_PASSWORD": os.environ.get("HUB_SMTP_PASSWORD", ""),
        "MICROSOFT_CLIENT_SECRET": os.environ.get("HUB_MICROSOFT_CLIENT_SECRET", ""),
        "TRIVY_SCHEDULER_ENABLED": _env_bool("HUB_TRIVY_SCHEDULER", True),
        "MAX_CONTENT_LENGTH": 8 * 1024 * 1024,  # requête HTTP complète
        "MAX_UPLOAD_BYTES": 4 * 1024 * 1024,  # screenshot
        "CERT_MAX_BYTES": 512 * 1024,  # certificat / clé / chaîne (chacun)
        "CERT_BUNDLE_MAX_BYTES": 256 * 1024,  # bundle PKCS#12 (.p12/.pfx)
        "PROJECT_URL": "https://github.com/Tetrax/hub",
    }
    if overrides:
        config.update(overrides)
    return config


def ensure_data_dirs(config: dict) -> None:
    """Crée les répertoires persistants et vérifie qu'ils sont inscriptibles.

    Le conteneur tourne sous un UID non privilégié (HUB_UID) : si le répertoire
    de données appartient à root (bind mount créé par Docker), il faut le
    préparer côté hôte — voir `scripts/prepare-data-dir.sh` et docs/operations.md.
    """
    uid, gid = os.getuid(), os.getgid()
    for key in ("DATA_DIR", "UPLOADS_DIR"):
        directory = Path(config[key])
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise RuntimeError(
                f"Répertoire de données non créé : {directory} ({error}). "
                f"Vérifier les droits du répertoire hôte (HUB_DATA_PATH) — "
                f"sudo scripts/prepare-data-dir.sh"
            ) from error
        if not os.access(directory, os.W_OK):
            raise RuntimeError(
                f"Répertoire de données non inscriptible : {directory} "
                f"(processus uid {uid} gid {gid}). Préparer le répertoire côté hôte : "
                f"sudo install -d -o {uid} -g {gid} <répertoire hôte> "
                f"(ou sudo scripts/prepare-data-dir.sh) — voir docs/operations.md."
            )


def ensure_secret_key(config: dict) -> str:
    """Retourne la clé de signature : HUB_SECRET_KEY, sinon générée et persistée."""
    from_env = os.environ.get("HUB_SECRET_KEY", "").strip()
    if from_env:
        return from_env
    key_file = Path(config["SECRET_KEY_FILE"])
    if key_file.exists():
        value = key_file.read_text(encoding="ascii").strip()
        if value:
            return value
    value = secrets.token_urlsafe(48)
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text(value + "\n", encoding="ascii")
    try:
        key_file.chmod(0o600)
    except OSError:
        pass
    return value
