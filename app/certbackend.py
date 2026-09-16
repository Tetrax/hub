"""Sélection du backend de gestion des certificats.

Trois backends, un seul code applicatif (aucune condition dispersée dans les
vues) :

- ``helper`` (défaut) : helper root via socket Unix — déploiement VPS ;
- ``proxy``           : proxy TLS de la stack (déploiement standalone) ;
- ``none``            : gestion désactivée — Hub derrière un TLS externe.

Les vues n'appellent que ces trois fonctions : ``get_status``,
``validate_certificate``, ``activate_certificate``.
"""

from __future__ import annotations

from flask import current_app

from . import certclient


class CertBackendError(RuntimeError):
    """Erreur utilisateur du backend (message déjà propre, affichable tel quel)."""


class DisabledBackend:
    """Aucune gestion de certificat (TLS assuré en amont)."""

    label = "none"

    def get_status(self) -> dict:
        return {
            "present": False,
            "certificate": None,
            "servedMatches": None,
            "backend": self.label,
            "disabled": True,
        }

    def validate_certificate(self, certificate: bytes, private_key: bytes, chain: bytes) -> dict:
        raise CertBackendError(
            "La gestion des certificats est désactivée pour ce déploiement "
            "(le TLS est assuré par l'infrastructure externe)."
        )

    def activate_certificate(self, ticket: str) -> dict:
        raise CertBackendError("La gestion des certificats est désactivée pour ce déploiement.")


class HelperBackend:
    """Helper root du VPS (socket Unix, pipeline Nginx complet)."""

    label = "helper"

    def get_status(self) -> dict:
        try:
            status = certclient.get_status()
        except certclient.CertHelperError as error:
            raise CertBackendError(str(error)) from error
        status.setdefault("backend", self.label)
        return status

    def validate_certificate(self, certificate: bytes, private_key: bytes, chain: bytes) -> dict:
        try:
            return certclient.validate_certificate(certificate, private_key, chain)
        except certclient.CertHelperError as error:
            raise CertBackendError(str(error)) from error

    def activate_certificate(self, ticket: str) -> dict:
        try:
            return certclient.activate_certificate(ticket)
        except certclient.CertHelperError as error:
            raise CertBackendError(str(error)) from error


def get_backend():
    """Backend configuré (``HUB_CERT_BACKEND``), construit à la demande."""
    from .certlocal import LocalTlsBackend

    config = current_app.config
    name = (config.get("CERT_BACKEND") or "helper").strip().lower()
    if name in {"local", "direct", "self"}:
        return LocalTlsBackend(
            certs_dir=config["CERTS_DIR"],
            hostname=config.get("TLS_HOSTNAME") or "",
            internal_host="127.0.0.1",
            internal_port=int(config["TLS_BIND_PORT"]),
            pidfile=config["GUNICORN_PIDFILE"],
        )
    if name in {"none", "disabled", "external"}:
        return DisabledBackend()
    return HelperBackend()
