"""Backend certificat « local » — TLS direct dans le conteneur (déploiement standalone).

Le Hub termine lui-même TLS (gunicorn + `--certfile/--keyfile`, voir
`app/gunicorn.conf.py`) et il est le seul gestionnaire de sa paire :

1. **validation** avec `hub_certctl` — mêmes règles que le helper root du VPS
   (dates, SAN vs `HUB_TLS_HOSTNAME`, clé ↔ certificat, ordre et signatures de
   chaîne, chargement TLS réel) ;
2. **écriture** d'une génération dans le volume `hub_certs` + bascule atomique du
   lien `active` (les générations précédentes sont conservées pour le rollback) ;
3. **rechargement** : signal `SIGHUP` au maître gunicorn (rechargement gracieux
   documenté ; les workers reconstruisent leur contexte SSL depuis les fichiers,
   donc le NOUVEAU certificat est présenté — sans redémarrer le conteneur) ;
4. **vérification réelle** : connexion TLS sur `127.0.0.1:<port interne>` avec
   `SNI = HUB_TLS_HOSTNAME` et comparaison de l'empreinte du certificat servi ;
5. **rollback** complet (génération précédente restaurée + rechargement +
   revérification) dès qu'une étape échoue.

Aucun accès hôte : ni systemd, ni Nginx, ni helper root, ni socket Docker.
"""

from __future__ import annotations

import os
import secrets
import shutil
import signal
import socket
import ssl
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import hub_certctl
except ImportError:  # exécution depuis le dépôt : le module vit dans helper/
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "helper"))
    import hub_certctl  # type: ignore[no-redef]

from .certbackend import CertBackendError

VALIDATION_TTL_SECONDS = 10 * 60
RELOAD_TIMEOUT_SECONDS = 20
VERIFY_INTERVAL_SECONDS = 0.4
BOOTSTRAP_MARKER = ".bootstrap"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _expiry_iso(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _fingerprint(cert_pem: bytes) -> str:
    return hub_certctl.certificate_fingerprint(cert_pem)


class LocalTlsBackend:
    """Paire TLS du serveur HTTPS du conteneur, activation + rechargement vérifiés."""

    label = "local"

    def __init__(
        self,
        *,
        certs_dir: str | Path,
        hostname: str,
        internal_host: str = "127.0.0.1",
        internal_port: int = 8443,
        pidfile: str | Path = "/tmp/gunicorn.pid",
        reload_timeout: float = RELOAD_TIMEOUT_SECONDS,
    ):
        self.certs_dir = Path(certs_dir)
        self.active_path = self.certs_dir / "active"
        self.staging_dir = self.certs_dir / "staging"
        self.marker_path = self.certs_dir / BOOTSTRAP_MARKER
        self.hostname = (hostname or "").strip()
        self.internal_host = internal_host
        self.internal_port = int(internal_port)
        self.pidfile = Path(pidfile)
        self.reload_timeout = float(reload_timeout)

    # --- Processus serveur ----------------------------------------------------

    def _master_pid(self) -> int:
        """PID du maître gunicorn, lu dans le fichier PID du serveur.

        Aucun repli deviné : envoyer un signal à un processus arbitraire serait
        dangereux. Sans fichier PID exploitable, l'activation refuse et l'explique.
        """
        if self.pidfile.is_file():
            try:
                pid = int(self.pidfile.read_text(encoding="ascii").strip())
            except (OSError, ValueError):
                pid = 0
            # PID 1 est légitime : dans un conteneur, gunicorn est le processus
            # principal. Toute valeur non exploitable est refusée explicitement.
            if pid >= 1:
                return pid
        raise CertBackendError(
            f"PID du serveur HTTPS introuvable ({self.pidfile}) : rechargement "
            "impossible (vérifier HUB_GUNICORN_PIDFILE et le démarrage du serveur)."
        )

    def _reload(self) -> None:
        """Rechargement gracieux : SIGHUP au maître, workers reconstruits."""
        pid = self._master_pid()
        try:
            os.kill(pid, signal.SIGHUP)
        except OSError as error:
            raise CertBackendError(
                "Le signal de rechargement du serveur HTTPS a échoué."
            ) from error

    # --- Vérification du certificat réellement servi --------------------------

    def _served_certificate(self) -> bytes | None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection(
                (self.internal_host, self.internal_port), timeout=5
            ) as raw:
                with context.wrap_socket(raw, server_hostname=self.hostname) as tls:
                    der = tls.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError):
            return None
        if not der:
            return None
        return ssl.DER_cert_to_PEM_cert(der).encode("ascii")

    def _wait_for_served(self, expected_fingerprint: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            served = self._served_certificate()
            if served is not None and _fingerprint(served) == expected_fingerprint:
                return True
            time.sleep(VERIFY_INTERVAL_SECONDS)
        return False

    def _served_details(self) -> dict | None:
        pem = self._served_certificate()
        if pem is None:
            return None
        details = {
            "fingerprintSha256": _fingerprint(pem),
            "subject": hub_certctl.certificate_name(pem, "subject"),
            "issuer": hub_certctl.certificate_name(pem, "issuer"),
            "commonName": hub_certctl.certificate_name(pem, "subject") or "",
        }
        try:
            not_before, not_after = hub_certctl.certificate_dates(pem)
            details["notBefore"] = not_before.strftime("%Y-%m-%dT%H:%M:%SZ")
            details["notAfter"] = not_after.strftime("%Y-%m-%dT%H:%M:%SZ")
        except hub_certctl.CertificateError:
            details["notBefore"] = details["notAfter"] = ""
        return details

    # --- État -----------------------------------------------------------------

    def get_status(self) -> dict:
        summary = None
        if self.hostname and (self.active_path / "fullchain.pem").is_file():
            try:
                summary = hub_certctl.active_summary(self.active_path, self.hostname)
            except hub_certctl.CertificateError:
                summary = None
        served = self._served_details()
        matches = None
        if summary and served:
            matches = served["fingerprintSha256"] == summary.get("fingerprintSha256")
        return {
            "backend": self.label,
            "hostname": self.hostname,
            "present": summary is not None,
            "certificate": summary,
            "served": served,
            "servedMatches": matches,
            "proxyReachable": served is not None,
            # Certificat temporaire de bootstrap : paire auto-signée créée au premier
            # démarrage, en attente du certificat définitif de la PKI du client.
            "bootstrap": self.marker_path.is_file() and summary is not None,
        }

    # --- Validation -----------------------------------------------------------

    def _purge_staging(self) -> None:
        if not self.staging_dir.is_dir():
            return
        limit = time.time() - VALIDATION_TTL_SECONDS
        for entry in self.staging_dir.iterdir():
            try:
                if entry.is_dir() and entry.stat().st_mtime < limit:
                    shutil.rmtree(entry, ignore_errors=True)
            except OSError:
                continue

    def validate_certificate(self, certificate: bytes, private_key: bytes, chain: bytes) -> dict:
        if not self.hostname:
            raise CertBackendError(
                "HUB_TLS_HOSTNAME doit être configuré (nom porté par le certificat)."
            )
        try:
            result = hub_certctl.validate_pair(certificate, private_key, chain, self.hostname)
        except hub_certctl.CertificateError as error:
            raise CertBackendError(str(error)) from error

        self._purge_staging()
        ticket = secrets.token_urlsafe(24)
        entry = self.staging_dir / ticket
        try:
            entry.mkdir(parents=True, exist_ok=True, mode=0o700)
            hub_certctl.write_durable(entry / "fullchain.pem", result["fullchain"], 0o644)
            hub_certctl.write_durable(entry / "privkey.pem", result["key"], 0o600)
        except OSError as error:
            shutil.rmtree(entry, ignore_errors=True)
            raise CertBackendError(
                "Impossible d'écrire la paire validée dans le volume de certificats "
                f"({error.__class__.__name__}). Vérifiez les droits du volume hub_certs."
            ) from error
        return {
            "ticket": ticket,
            "expiresAt": _expiry_iso(VALIDATION_TTL_SECONDS),
            "summary": result["summary"],
        }

    # --- Activation -----------------------------------------------------------

    def _staging_entry(self, ticket: str) -> Path:
        if not ticket or "/" in ticket or not self.staging_dir.is_dir():
            raise CertBackendError("Validation introuvable ou expirée ; relancez la validation.")
        entry = self.staging_dir / ticket
        if not (entry / "fullchain.pem").is_file() or not (entry / "privkey.pem").is_file():
            raise CertBackendError("Validation introuvable ou expirée ; relancez la validation.")
        if time.time() - entry.stat().st_mtime > VALIDATION_TTL_SECONDS:
            shutil.rmtree(entry, ignore_errors=True)
            raise CertBackendError("Validation expirée ; relancez la validation.")
        return entry

    def activate_certificate(self, ticket: str) -> dict:
        entry = self._staging_entry(ticket)
        try:
            fullchain = (entry / "fullchain.pem").read_bytes()
            key_pem = (entry / "privkey.pem").read_bytes()
            blocks = hub_certctl.certificate_blocks(fullchain)
            if not blocks:
                raise CertBackendError("Certificat illisible ; relancez la validation.")
            expected = _fingerprint(blocks[0])

            self.certs_dir.mkdir(parents=True, exist_ok=True)
            previous = hub_certctl.current_generation(self.active_path)
            generation = hub_certctl.activate(self.active_path, fullchain, key_pem)
            try:
                self._reload()
                if not self._wait_for_served(expected, self.reload_timeout):
                    raise CertBackendError(
                        "Le certificat présenté par le serveur HTTPS ne correspond pas "
                        "au certificat activé."
                    )
            except Exception as error:  # noqa: BLE001 — rollback systématique
                hub_certctl.restore(self.active_path, previous)
                hub_certctl.cleanup_generation(self.certs_dir, generation)
                warning = ""
                if previous:
                    try:
                        self._reload()
                        current = (self.active_path / "fullchain.pem").read_bytes()
                        restored_fp = _fingerprint(hub_certctl.certificate_blocks(current)[0])
                        if not self._wait_for_served(restored_fp, self.reload_timeout):
                            warning = (
                                " Le certificat présenté ne correspond pas non plus à la paire "
                                "précédente : intervention nécessaire sur le conteneur."
                            )
                    except Exception:  # noqa: BLE001 — signalé, jamais masqué
                        warning = (
                            " Le serveur HTTPS n'a pas pu être rechargé avec la paire "
                            "précédente : intervention nécessaire sur le conteneur."
                        )
                raise CertBackendError(
                    f"Activation refusée : {error} — paire précédente restaurée.{warning}"
                ) from error

            summary = hub_certctl.build_summary(fullchain, self.hostname)
            hub_certctl.cleanup_generation(self.certs_dir, previous)
            # Le certificat définitif remplace le certificat temporaire de bootstrap.
            try:
                self.marker_path.unlink()
            except FileNotFoundError:
                pass
            return {
                "ok": True,
                "backend": self.label,
                "generation": generation,
                "previous": previous,
                "summary": summary,
                "servedMatches": True,
            }
        except hub_certctl.CertificateError as error:
            raise CertBackendError(str(error)) from error
        except OSError as error:
            raise CertBackendError(
                "Impossible d'installer la paire dans le volume de certificats "
                f"({error.__class__.__name__}). Vérifiez les droits du volume hub_certs."
            ) from error
        finally:
            if entry.is_dir():
                shutil.rmtree(entry, ignore_errors=True)


# --- Amorçage du certificat temporaire (premier démarrage) --------------------


def bootstrap_certificate(certs_dir: str | Path, hostname: str, days: int = 30) -> str | None:
    """Crée (ou recrée) le certificat temporaire de bootstrap si nécessaire.

    Appelé par l'entrypoint du conteneur AVANT le démarrage du serveur : gunicorn
    refuse de démarrer sans paire lisible. Le certificat est auto-signé, couvre le
    nom demandé, vit dans le volume `hub_certs` (il survit aux redémarrages) et
    porte le marqueur ``.bootstrap`` : il est donc annoncé comme temporaire dans
    l'interface et remplacé automatiquement à la première activation réelle.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    certs_dir = Path(certs_dir)
    active_path = certs_dir / "active"
    marker_path = certs_dir / BOOTSTRAP_MARKER
    hostname = (hostname or "").strip()
    if not hostname:
        raise SystemExit("HUB_HOSTNAME ou HUB_TLS_HOSTNAME est requis pour le bootstrap TLS.")

    existing = active_path / "fullchain.pem"
    if existing.is_file():
        if not marker_path.is_file():
            return None  # paire définitive en place : ne rien toucher
        try:
            _, not_after = hub_certctl.certificate_dates(existing.read_bytes())
        except hub_certctl.CertificateError:
            not_after = None
        if not_after is not None and not_after > datetime.now(timezone.utc) + timedelta(days=3):
            return None  # bootstrap encore valable : le conserver

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    fullchain = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    certs_dir.mkdir(parents=True, exist_ok=True)
    previous = hub_certctl.current_generation(active_path)
    generation = hub_certctl.activate(active_path, fullchain, key_pem)
    hub_certctl.cleanup_generation(certs_dir, previous)
    marker_path.write_text(
        f"certificat temporaire de bootstrap pour {hostname}\n", encoding="utf-8"
    )
    return generation


def main(argv: list[str]) -> int:
    if len(argv) >= 1 and argv[0] == "bootstrap":
        certs_dir = argv[1] if len(argv) > 1 else os.environ.get("HUB_CERTS_DIR", "/certs")
        hostname = (
            os.environ.get("HUB_TLS_HOSTNAME") or os.environ.get("HUB_HOSTNAME") or ""
        ).strip()
        try:
            generation = bootstrap_certificate(certs_dir, hostname)
        except SystemExit as error:
            print(str(error), file=sys.stderr)
            return 2
        except Exception:  # noqa: BLE001 — diagnostic utile dans les journaux
            traceback.print_exc()
            return 1
        if generation:
            print(f"[hub] certificat temporaire de bootstrap activé ({generation})")
        else:
            print("[hub] paire TLS déjà en place : aucun bootstrap nécessaire")
        return 0
    print("Usage : python -m app.certlocal bootstrap [répertoire]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
