#!/usr/bin/env python3
"""Helper privilégié d'activation des certificats SNS Hub (service systemd root).

Deux interfaces :

- **socket Unix privée** (application web) : `ping`, `status`, `validate`,
  `activate` — la paire candidate voyage par la socket, jamais par un volume
  inscriptible par l'application ;
- **CLI root** : `serve`, `ping`, `status`, `install` (amorçage), `renew`
  (hook certbot `RENEWED_LINEAGE`).

Frontières de sécurité :

- socket 0660 root:<gid applicatif>, répertoire 0750, pair vérifié par
  `SO_PEERCRED` (uid et gid attendus) ;
- la clé privée n'est jamais renvoyée ni journalisée (métadonnées publiques) ;
- toute activation passe par `hub_certctl` : validation complète, génération
  immuable, bascule atomique, `nginx -t`, reload, vérification du certificat
  réellement servi, rollback automatique en cas d'échec.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

import hub_certctl
import hub_cert_lock

try:
    import hub_cert_protocol as protocol  # type: ignore[import-not-found]
except ImportError:  # exécution depuis le dépôt, avant installation dans /opt
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
    import hub_cert_protocol as protocol  # type: ignore[import-not-found]

DEFAULT_SOCKET = Path("/run/hub-cert-helper/helper.sock")
DEFAULT_OUTPUT = Path("/var/lib/hub/certificates/active")
REQUEST_TIMEOUT_SECONDS = 30.0
VALIDATION_TTL_SECONDS = 10 * 60
MAX_STAGING_ENTRIES = 8
MAX_FIELD_BYTES = 512 * 1024
TICKET_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
PAYLOAD_KEYS = {"certificateBase64", "privateKeyBase64", "chainBase64"}


class HelperAuthorizationError(PermissionError):
    """Le processus pair n'est pas le processus applicatif attendu."""


class CertificateReloadError(RuntimeError):
    """Nginx a refusé la configuration ou le certificat servi ne correspond pas."""


def peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise HelperAuthorizationError("SO_PEERCRED est indisponible.")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


# --- Contrôle Nginx ----------------------------------------------------------


class NginxController:
    """`nginx -t`, reload et vérification du certificat réellement servi."""

    def __init__(self, nginx_bin: str, systemctl_bin: str, hostname: str, https_port: int):
        self.nginx_bin = nginx_bin
        self.systemctl_bin = systemctl_bin
        self.hostname = hostname
        self.https_port = https_port

    def test_config(self) -> None:
        try:
            subprocess.run(
                [self.nginx_bin, "-t"], capture_output=True, check=True, timeout=15
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise CertificateReloadError("Nginx a refusé la configuration (nginx -t).") from error

    def reload(self) -> None:
        try:
            subprocess.run(
                [self.systemctl_bin, "reload", "nginx"],
                capture_output=True,
                check=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise CertificateReloadError("Échec du rechargement de Nginx.") from error

    def served_fingerprint(self) -> str | None:
        """Empreinte SHA-256 du certificat réellement présenté par Nginx (best effort)."""
        try:
            result = subprocess.run(
                [
                    "openssl",
                    "s_client",
                    "-connect",
                    f"127.0.0.1:{self.https_port}",
                    "-servername",
                    self.hostname,
                    "-showcerts",
                ],
                input=b"",
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        blocks = hub_certctl.certificate_blocks(result.stdout)
        if not blocks:
            return None
        try:
            return hub_certctl.certificate_fingerprint(blocks[0])
        except hub_certctl.CertificateError:
            return None

    def verify_served(self, expected_fingerprint: str, attempts: int = 5, delay: float = 0.4) -> None:
        expected = _normalize_fingerprint(expected_fingerprint)
        for _ in range(attempts):
            served = self.served_fingerprint()
            if served and _normalize_fingerprint(served) == expected:
                return
            time.sleep(delay)
        raise CertificateReloadError(
            "Le certificat servi par Nginx ne correspond pas au certificat activé "
            "(vérification HTTPS échouée)."
        )


def _normalize_fingerprint(value: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()


# --- Processeur --------------------------------------------------------------


class CertHelperProcessor:
    def __init__(
        self,
        *,
        hostname: str,
        output_dir: Path,
        staging_dir: Path,
        allowed_uid: int,
        allowed_gid: int,
        nginx: NginxController | None,
    ) -> None:
        if not hostname:
            raise ValueError("HUB_TLS_HOSTNAME doit être configuré.")
        if allowed_uid <= 0 or allowed_gid <= 0:
            raise ValueError("HUB_PUID et HUB_PGID doivent être strictement supérieurs à zéro.")
        self.hostname = hostname
        self.output_dir = Path(output_dir)
        self.staging_dir = Path(staging_dir)
        self.allowed_uid = allowed_uid
        self.allowed_gid = allowed_gid
        self.nginx = nginx
        # Le helper root possède cet arbre : il l'initialise (idempotent) pour que
        # `status` fonctionne même avant la première activation.
        self.output_dir.parent.mkdir(mode=0o755, parents=True, exist_ok=True)

    # -- staging ---------------------------------------------------------

    def _purge_expired(self) -> None:
        now = time.time()
        if not self.staging_dir.is_dir():
            return
        for entry in self.staging_dir.iterdir():
            if not entry.is_dir():
                continue
            meta = self._read_meta(entry)
            if meta is None or float(meta.get("expiresAtEpoch", 0)) <= now:
                shutil.rmtree(entry, ignore_errors=True)

    @staticmethod
    def _read_meta(entry: Path) -> dict | None:
        meta_path = entry / "meta.json"
        try:
            return json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _write_meta(self, entry: Path, ticket: str) -> str:
        expires_at = time.time() + VALIDATION_TTL_SECONDS
        meta = {
            "ticketHash": hashlib.sha256(ticket.encode("ascii")).hexdigest(),
            "expiresAtEpoch": expires_at,
            "expiresAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at)),
            "hostname": self.hostname,
        }
        path = entry / "meta.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(meta, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        return meta["expiresAt"]

    def _find_staging(self, ticket: str) -> Path | None:
        ticket_hash = hashlib.sha256(ticket.encode("ascii")).hexdigest()
        if not self.staging_dir.is_dir():
            return None
        for entry in self.staging_dir.iterdir():
            if not entry.is_dir():
                continue
            meta = self._read_meta(entry)
            if meta and meta.get("ticketHash") == ticket_hash:
                return entry
        return None

    # -- opérations ------------------------------------------------------

    def status(self) -> dict:
        with hub_cert_lock.certificate_directory_lock(
            self.output_dir.parent, exclusive=False, create=True
        ):
            summary = hub_certctl.active_summary(self.output_dir, self.hostname)
        result: dict = {
            "ok": True,
            "hostname": self.hostname,
            "present": summary is not None,
            "certificate": summary,
        }
        if summary is not None and self.nginx is not None:
            served = self.nginx.served_fingerprint()
            result["servedMatches"] = (
                _normalize_fingerprint(served) == _normalize_fingerprint(summary["fingerprintSha256"])
                if served
                else None
            )
        else:
            result["servedMatches"] = None
        return result

    def validate(self, payload: object) -> dict:
        certificate, private_key, chain = self._decode_payload(payload)
        self._purge_expired()
        self.staging_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        pending = [entry for entry in self.staging_dir.iterdir() if entry.is_dir()]
        if len(pending) >= MAX_STAGING_ENTRIES:
            raise protocol.ProtocolError(
                "Trop de validations en attente ; réessayez dans quelques minutes."
            )
        result = hub_certctl.validate_pair(certificate, private_key, chain, self.hostname)
        ticket = secrets.token_urlsafe(32)
        entry = self.staging_dir / secrets.token_hex(8)
        entry.mkdir(mode=0o700)
        try:
            hub_certctl.write_durable(entry / "fullchain.pem", result["fullchain"], 0o600)
            hub_certctl.write_durable(entry / "privkey.pem", result["key"], 0o600)
            expires_at = self._write_meta(entry, ticket)
        except BaseException:
            shutil.rmtree(entry, ignore_errors=True)
            raise
        return {
            "ok": True,
            "ticket": ticket,
            "expiresAt": expires_at,
            "summary": result["summary"],
        }

    def activate(self, ticket: str) -> dict:
        if not TICKET_RE.match(ticket or ""):
            raise protocol.ProtocolError("Ticket de validation invalide.")
        self._purge_expired()
        entry = self._find_staging(ticket)
        if entry is None:
            raise protocol.ProtocolError(
                "Validation introuvable ou expirée ; relancez la validation."
            )
        try:
            fullchain = (entry / "fullchain.pem").read_bytes()
            key_pem = (entry / "privkey.pem").read_bytes()
            result = hub_certctl.validate_pair(fullchain, key_pem, b"", self.hostname)
            installed = self.install(result["fullchain"], result["key"], result["summary"])
        finally:
            shutil.rmtree(entry, ignore_errors=True)
        return {"ok": True, **installed}

    def install(self, fullchain: bytes, key_pem: bytes, summary: dict) -> dict:
        """Activation complète : bascule atomique, Nginx, vérification, rollback."""
        parent = self.output_dir.parent
        with hub_cert_lock.certificate_directory_lock(parent, exclusive=True):
            previous = hub_certctl.current_generation(self.output_dir)
            if self.nginx is not None:
                self.nginx.test_config()
            new_generation = hub_certctl.activate(self.output_dir, fullchain, key_pem)
            try:
                if self.nginx is not None:
                    self.nginx.test_config()
                    self.nginx.reload()
                    self.nginx.verify_served(summary["fingerprintSha256"])
            except Exception:
                hub_certctl.restore(self.output_dir, previous)
                hub_certctl.cleanup_generation(parent, new_generation)
                if self.nginx is not None:
                    try:
                        self.nginx.test_config()
                        self.nginx.reload()
                    except Exception as rollback_error:
                        raise CertificateReloadError(
                            "Échec du rechargement Nginx et du rechargement après rollback."
                        ) from rollback_error
                raise
            hub_certctl.cleanup_generation(parent, previous)
        return {"previous": previous, "summary": summary}

    def _decode_payload(self, payload: object) -> tuple[bytes, bytes, bytes]:
        if not isinstance(payload, dict) or set(payload) != PAYLOAD_KEYS:
            raise protocol.ProtocolError("Payload de validation invalide.")
        decoded: dict[str, bytes] = {}
        for name in PAYLOAD_KEYS:
            raw = payload.get(name)
            if not isinstance(raw, str):
                raise protocol.ProtocolError("Payload de validation invalide.")
            if len(raw) > MAX_FIELD_BYTES * 2:
                raise protocol.ProtocolError("Fichier trop volumineux.")
            try:
                decoded[name] = base64.b64decode(raw, validate=True)
            except (binascii.Error, ValueError) as error:
                raise protocol.ProtocolError("Encodage base64 invalide.") from error
        for name, label in (
            ("certificateBase64", "Le certificat"),
            ("privateKeyBase64", "La clé privée"),
            ("chainBase64", "La chaîne"),
        ):
            if len(decoded[name]) > MAX_FIELD_BYTES:
                raise protocol.ProtocolError(f"{label} est trop volumineux (512 Ko maximum).")
        return decoded["certificateBase64"], decoded["privateKeyBase64"], decoded["chainBase64"]

    # -- protocole -------------------------------------------------------

    def process(self, message: dict, *, peer_uid: int, peer_gid: int) -> dict:
        if message.get("version") != protocol.PROTOCOL_VERSION:
            raise protocol.ProtocolError("Version de protocole invalide.")
        action = message.get("action")
        if action == "ping":
            if set(message) != {"version", "action"}:
                raise protocol.ProtocolError("Requête ping invalide.")
            if peer_uid not in {0, self.allowed_uid}:
                raise HelperAuthorizationError("Processus pair non autorisé.")
            return {"ok": True, "version": protocol.PROTOCOL_VERSION}
        if peer_uid != self.allowed_uid or peer_gid != self.allowed_gid:
            raise HelperAuthorizationError("Processus pair non autorisé.")
        if action == "status":
            if set(message) != {"version", "action"}:
                raise protocol.ProtocolError("Requête status invalide.")
            return self.status()
        if action == "validate":
            if set(message) != {"version", "action", "payload"}:
                raise protocol.ProtocolError("Requête de validation invalide.")
            return self.validate(message.get("payload"))
        if action == "activate":
            if set(message) != {"version", "action", "ticket"} or not isinstance(
                message.get("ticket"), str
            ):
                raise protocol.ProtocolError("Requête d'activation invalide.")
            return self.activate(message["ticket"])
        raise protocol.ProtocolError("Opération interdite par le helper.")


# --- Serveur socket ----------------------------------------------------------


class _RequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        connection = self.request
        connection.settimeout(REQUEST_TIMEOUT_SECONDS)
        processor: CertHelperProcessor = self.server.processor  # type: ignore[attr-defined]
        try:
            _, peer_uid, peer_gid = peer_credentials(connection)
            message = protocol.receive_message(
                connection, maximum_bytes=protocol.MAX_REQUEST_BYTES
            )
            response = processor.process(message, peer_uid=peer_uid, peer_gid=peer_gid)
        except protocol.ProtocolError as error:
            response = {"ok": False, "error": str(error)[:1000], "errorCode": "protocol_error"}
        except HelperAuthorizationError:
            response = {
                "ok": False,
                "error": "Processus pair non autorisé.",
                "errorCode": "unauthorized",
            }
        except hub_certctl.CertificateError as error:
            response = {"ok": False, "error": str(error)[:1000], "errorCode": "validation_failed"}
        except CertificateReloadError as error:
            response = {"ok": False, "error": str(error)[:1000], "errorCode": "reload_failed"}
        except (OSError, ValueError) as error:
            message = re.sub(r"/var/lib/hub/certificates/[^\s:]+", "<génération>", str(error))
            response = {"ok": False, "error": message[:1000], "errorCode": "io_error"}
        except Exception as error:  # noqa: BLE001 — jamais de détail interne au client
            print(
                f"Erreur interne du helper certificat : {type(error).__name__}",
                file=sys.stderr,
            )
            response = {"ok": False, "error": "Erreur interne du helper certificat."}
        try:
            protocol.send_message(connection, response, maximum_bytes=protocol.MAX_RESPONSE_BYTES)
        except (protocol.ProtocolError, OSError):
            return


class CertHelperServer(socketserver.UnixStreamServer):
    request_queue_size = 4

    def __init__(self, socket_path: Path, processor: CertHelperProcessor, *, socket_gid: int | None):
        if not socket_path.is_absolute():
            raise ValueError("Le chemin de socket du helper doit être absolu.")
        self.socket_path = socket_path
        self.processor = processor
        self._socket_identity: tuple[int, int] | None = None
        self._prepare_socket_directory(socket_gid)
        self._remove_stale_socket()
        super().__init__(str(socket_path), _RequestHandler)
        if socket_gid is not None:
            os.chown(socket_path, 0, socket_gid)
        socket_path.chmod(0o660)
        current = socket_path.stat()
        self._socket_identity = (current.st_dev, current.st_ino)

    def _prepare_socket_directory(self, socket_gid: int | None) -> None:
        directory = self.socket_path.parent
        try:
            current = directory.lstat()
        except FileNotFoundError as error:
            raise ValueError("Le répertoire du socket helper doit exister.") from error
        if (
            not stat.S_ISDIR(current.st_mode)
            or directory.is_symlink()
            or current.st_uid not in {0, os.geteuid()}
        ):
            raise ValueError("Le répertoire du socket helper n'est pas un répertoire géré sûr.")
        if socket_gid is not None:
            os.chown(directory, 0, socket_gid)
        directory.chmod(0o750)

    def _remove_stale_socket(self) -> None:
        try:
            current = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(current.st_mode) or current.st_uid not in {0, os.geteuid()}:
            raise ValueError("Le chemin du helper existe et n'est pas un socket géré sûr.")
        self.socket_path.unlink()

    def server_close(self) -> None:
        super().server_close()
        try:
            current = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if self._socket_identity == (current.st_dev, current.st_ino) and stat.S_ISSOCK(
            current.st_mode
        ):
            self.socket_path.unlink()

    def handle_error(self, request, client_address) -> None:  # noqa: ARG002
        print("Erreur de traitement isolée dans le helper certificat.", file=sys.stderr)


# --- Configuration et CLI ----------------------------------------------------


def load_env_config() -> dict:
    output_dir = Path(os.environ.get("HUB_CERT_OUTPUT_DIR", str(DEFAULT_OUTPUT)))
    return {
        "hostname": os.environ.get("HUB_TLS_HOSTNAME", "").strip(),
        "output_dir": output_dir,
        "staging_dir": Path(
            os.environ.get("HUB_CERT_STAGING_DIR", str(output_dir.parent / "staging"))
        ),
        "socket_path": Path(os.environ.get("HUB_CERT_HELPER_SOCKET", str(DEFAULT_SOCKET))),
        "allowed_uid": int(os.environ.get("HUB_PUID", "1000")),
        "allowed_gid": int(os.environ.get("HUB_PGID", "1000")),
        "reload_nginx": os.environ.get("HUB_CERT_RELOAD_NGINX", "0") == "1",
        "nginx_bin": os.environ.get("HUB_NGINX_BIN", "/usr/sbin/nginx"),
        "systemctl_bin": os.environ.get("HUB_SYSTEMCTL", "/usr/bin/systemctl"),
        "https_port": int(os.environ.get("HUB_HTTPS_PORT", "443")),
    }


def build_processor(config: dict, *, force_reload: bool | None = None) -> CertHelperProcessor:
    nginx = None
    enabled = config["reload_nginx"] if force_reload is None else force_reload
    if enabled:
        nginx = NginxController(
            config["nginx_bin"], config["systemctl_bin"], config["hostname"], config["https_port"]
        )
    return CertHelperProcessor(
        hostname=config["hostname"],
        output_dir=config["output_dir"],
        staging_dir=config["staging_dir"],
        allowed_uid=config["allowed_uid"],
        allowed_gid=config["allowed_gid"],
        nginx=nginx,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("serve")
    subparsers.add_parser("ping")
    subparsers.add_parser("status")
    subparsers.add_parser("renew")
    install = subparsers.add_parser("install", help="Valider et installer une paire (root).")
    install.add_argument("--cert", type=Path, required=True)
    install.add_argument("--key", type=Path, required=True)
    install.add_argument("--chain", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    config = load_env_config()
    if args.command == "ping":
        try:
            response = protocol.request_helper(
                config["socket_path"],
                {"version": protocol.PROTOCOL_VERSION, "action": "ping"},
                timeout_seconds=5,
                response_timeout_seconds=5,
            )
        except protocol.HelperUnavailable as error:
            print(str(error), file=sys.stderr)
            return 1
        return 0 if response.get("ok") is True else 1

    if os.geteuid() != 0:
        print("Le helper certificat doit être exécuté en root.", file=sys.stderr)
        return 77

    try:
        processor = build_processor(config)
    except (OSError, ValueError) as error:
        print(f"Configuration du helper certificat invalide : {error}", file=sys.stderr)
        return 78

    if args.command == "status":
        try:
            result = processor.status()
        except hub_certctl.CertificateError as error:
            print(f"Erreur certificat : {error}", file=sys.stderr)
            return 1
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command in {"install", "renew"}:
        if processor.nginx is None:
            # Mode sans Nginx local (HUB_CERT_RELOAD_NGINX=0) : l'activation se
            # limite à la bascule atomique — pas de `nginx -t`, pas de
            # rechargement, pas de vérification du certificat réellement servi.
            # C'est un choix d'exploitation explicite (TLS terminé en amont).
            print(
                "Attention : HUB_CERT_RELOAD_NGINX=0 — activation sans test, sans "
                "rechargement Nginx et sans vérification du certificat servi.",
                file=sys.stderr,
            )
        if args.command == "renew":
            lineage = Path(os.environ.get("RENEWED_LINEAGE", ""))
            if not lineage or not (lineage / "fullchain.pem").is_file():
                print("RENEWED_LINEAGE est requis pour le renouvellement.", file=sys.stderr)
                return 78
            cert_path, key_path, chain_path = (
                lineage / "fullchain.pem",
                lineage / "privkey.pem",
                None,
            )
        else:
            cert_path, key_path, chain_path = args.cert, args.key, args.chain
        try:
            certificate = cert_path.read_bytes()
            key_pem = key_path.read_bytes()
            chain = chain_path.read_bytes() if chain_path else b""
            result = hub_certctl.validate_pair(certificate, key_pem, chain, config["hostname"])
            installed = processor.install(result["fullchain"], result["key"], result["summary"])
        except (hub_certctl.CertificateError, CertificateReloadError, OSError) as error:
            print(f"Erreur d'installation du certificat : {error}", file=sys.stderr)
            return 1
        print(
            json.dumps(
                {
                    "ok": True,
                    "previous": installed.get("previous"),
                    "notAfter": installed["summary"]["notAfter"],
                    "fingerprintSha256": installed["summary"]["fingerprintSha256"],
                },
                ensure_ascii=False,
            )
        )
        return 0

    # serve
    try:
        processor.staging_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        processor._purge_expired()  # noqa: SLF001 — entretien au démarrage
        server = CertHelperServer(
            config["socket_path"], processor, socket_gid=config["allowed_gid"]
        )
    except (OSError, ValueError) as error:
        print(f"Configuration du helper certificat invalide : {error}", file=sys.stderr)
        return 78
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
