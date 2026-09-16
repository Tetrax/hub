"""Client applicatif du helper certificat (socket Unix).

L'application ne touche jamais les fichiers du certificat : elle envoie la paire
candidate au helper root, qui valide, active et recharge Nginx.
"""

from __future__ import annotations

import base64

from flask import current_app

from .hub_cert_protocol import (
    ACTIVATION_TIMEOUT_SECONDS,
    PROTOCOL_VERSION,
    HelperUnavailable,
    request_helper,
)


class CertHelperError(RuntimeError):
    """Erreur utilisateur remontée depuis le helper (message déjà propre)."""


def _socket_path() -> str:
    path = current_app.config.get("CERT_HELPER_SOCKET", "")
    if not path:
        raise CertHelperError("Socket du helper certificat non configurée.")
    return path


def _call(action: str, extra: dict | None = None, *, timeout: float | None = None) -> dict:
    message = {"version": PROTOCOL_VERSION, "action": action}
    if extra:
        message.update(extra)
    kwargs = {}
    if timeout is not None:
        kwargs = {"timeout_seconds": timeout, "response_timeout_seconds": timeout}
    try:
        response = request_helper(_socket_path(), message, **kwargs)
    except HelperUnavailable as error:
        raise CertHelperError(str(error)) from error
    if response.get("ok") is not True:
        raise CertHelperError(str(response.get("error") or "Opération refusée par le helper."))
    return response


def ping() -> bool:
    try:
        _call("ping", timeout=5)
        return True
    except CertHelperError:
        return False


def get_status() -> dict:
    """État du certificat actif. Retourne {'present': bool, ...}."""
    return _call("status")


def validate_certificate(certificate: bytes, private_key: bytes, chain: bytes = b"") -> dict:
    """Prévalidation : retourne {ticket, expiresAt, summary} sans rien activer."""
    payload = {
        "certificateBase64": base64.b64encode(certificate).decode("ascii"),
        "privateKeyBase64": base64.b64encode(private_key).decode("ascii"),
        "chainBase64": base64.b64encode(chain).decode("ascii"),
    }
    return _call("validate", {"payload": payload})


def activate_certificate(ticket: str) -> dict:
    """Active la paire prévalidée (bascule atomique + Nginx + vérification HTTPS)."""
    return _call("activate", {"ticket": ticket}, timeout=ACTIVATION_TIMEOUT_SECONDS)
