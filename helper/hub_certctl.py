"""Validation, normalisation et activation atomique des paires TLS de SNS Hub.

Mécanisme autoritatif unique : toute installation de certificat (assistée par
l'admin, amorçage, renouvellement Let's Encrypt) passe par ces fonctions,
exécutées par le helper root.

Principes repris du mécanisme FortiUpgrade (analysé en phase 1) :
- validation complète avant activation (format, dates, SAN/FQDN, appariement
  clé/certificat, chaîne, chargement TLS effectif) ;
- générations immuables `.active-<hash>` + lien symbolique `active` basculé par
  `os.replace` (atomique) ;
- l'ancienne génération n'est supprimée qu'après vérification complète de la
  nouvelle (rollback possible à tout moment) ;
- clé privée en 0600, jamais journalisée, jamais renvoyée par la socket.
"""

from __future__ import annotations

import itertools
import os
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

CERTIFICATE_BLOCK_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----\s*", re.DOTALL
)
OPENSSL = "openssl"
OPENSSL_TIMEOUT = 30


class CertificateError(RuntimeError):
    """Le certificat ne peut pas être validé ou installé de façon sûre."""


def _sanitize(message: str) -> str:
    return re.sub(r"/tmp/[^\s:]+", "<temporaire>", str(message))[:800]


def run_openssl(*args: str, input_data: bytes | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [OPENSSL, *args],
        input=input_data,
        capture_output=True,
        timeout=OPENSSL_TIMEOUT,
        check=False,
    )
    if result.returncode:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise CertificateError(_sanitize(message) or "Commande OpenSSL refusée.")
    return result


# --- Analyse et validation ---------------------------------------------------


def certificate_blocks(data: bytes) -> list[bytes]:
    return CERTIFICATE_BLOCK_RE.findall(data or b"")


def normalize_certificate(cert_pem: bytes) -> bytes:
    return run_openssl("x509", "-outform", "PEM", input_data=cert_pem).stdout


def normalize_private_key(key_pem: bytes) -> bytes:
    return run_openssl("pkey", input_data=key_pem).stdout


def _x509_text(cert_pem: bytes, *args: str) -> str:
    return run_openssl("x509", "-noout", *args, input_data=cert_pem).stdout.decode(
        "utf-8", errors="replace"
    )


def certificate_name(cert_pem: bytes, field: str) -> str:
    raw = _x509_text(cert_pem, f"-{field}", "-nameopt", "RFC2253").strip()
    return raw.split("=", 1)[1] if "=" in raw else raw


def certificate_dates(cert_pem: bytes) -> tuple[datetime, datetime]:
    text = _x509_text(cert_pem, "-startdate", "-enddate")
    values: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if separator:
            values[name.strip()] = " ".join(value.split())
    try:
        not_before = parsedate_to_datetime(values["notBefore"])
        not_after = parsedate_to_datetime(values["notAfter"])
    except (KeyError, ValueError) as error:
        raise CertificateError("Dates du certificat illisibles.") from error
    return not_before, not_after


def validate_dates(cert_pem: bytes, label: str) -> None:
    not_before, not_after = certificate_dates(cert_pem)
    now = datetime.now(timezone.utc)
    if not_after <= now:
        raise CertificateError(f"Le certificat {label} est expiré.")
    if not_before > now:
        raise CertificateError(f"Le certificat {label} n'est pas encore valide.")


def san_dns_names(cert_pem: bytes) -> list[str]:
    text = _x509_text(cert_pem, "-ext", "subjectAltName")
    if "DNS:" not in text:
        return []
    return re.findall(r"DNS:([^,\s]+)", text)


def check_hostname(cert_pem: bytes, hostname: str) -> None:
    result = subprocess.run(
        [OPENSSL, "x509", "-noout", "-checkhost", hostname],
        input=cert_pem,
        capture_output=True,
        timeout=OPENSSL_TIMEOUT,
        check=False,
    )
    expected = f"Hostname {hostname} does match certificate".encode()
    if result.returncode != 0 or result.stdout.strip() != expected:
        raise CertificateError(f"Le certificat ne couvre pas le nom d'hôte {hostname}.")


def public_key_from_certificate(cert_pem: bytes) -> bytes:
    pem = run_openssl("x509", "-pubkey", "-noout", input_data=cert_pem).stdout
    return run_openssl("pkey", "-pubin", "-outform", "DER", input_data=pem).stdout


def public_key_from_private_key(key_pem: bytes) -> bytes:
    return run_openssl("pkey", "-pubout", "-outform", "DER", input_data=key_pem).stdout


def order_chain(leaf_pem: bytes, chain: list[bytes]) -> list[bytes]:
    if any(certificate == leaf_pem for certificate in chain) or len(set(chain)) != len(chain):
        raise CertificateError("La chaîne contient le certificat feuille ou un doublon.")
    remaining = list(chain)
    ordered: list[bytes] = []
    current = leaf_pem
    while remaining:
        issuer = certificate_name(current, "issuer")
        matches = [cert for cert in remaining if certificate_name(cert, "subject") == issuer]
        if len(matches) != 1:
            raise CertificateError("La chaîne est ambiguë ou ne correspond pas au certificat.")
        current = matches[0]
        remaining.remove(current)
        ordered.append(current)
    return ordered


def validate_chain(leaf_pem: bytes, chain: list[bytes]) -> list[bytes]:
    ordered = order_chain(leaf_pem, chain) if chain else []
    for index, certificate in enumerate([leaf_pem, *ordered]):
        validate_dates(certificate, "feuille" if index == 0 else f"de chaîne {index}")
    for child, issuer in itertools.pairwise([leaf_pem, *ordered]):
        if certificate_name(child, "issuer") != certificate_name(issuer, "subject"):
            raise CertificateError(
                "La chaîne n'est pas ordonnée ou ne correspond pas au certificat."
            )
    if ordered:
        with tempfile.TemporaryDirectory(prefix="hub-chain-") as temporary:
            directory = Path(temporary)
            leaf_path = directory / "leaf.pem"
            trusted_path = directory / "trusted.pem"
            leaf_path.write_bytes(leaf_pem)
            trusted_path.write_bytes(ordered[-1])
            arguments = [
                "verify",
                "-partial_chain",
                "-purpose",
                "sslserver",
                "-trusted",
                str(trusted_path),
            ]
            if len(ordered) > 1:
                intermediates = directory / "intermediates.pem"
                intermediates.write_bytes(b"".join(ordered[:-1]))
                arguments.extend(["-untrusted", str(intermediates)])
            run_openssl(*arguments, str(leaf_path))
    return ordered


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def certificate_fingerprint(cert_pem: bytes) -> str:
    return _x509_text(cert_pem, "-fingerprint", "-sha256").strip().split("=", 1)[-1].strip()


def build_summary(fullchain: bytes, hostname: str) -> dict:
    blocks = certificate_blocks(fullchain)
    if not blocks:
        raise CertificateError("Certificat illisible.")
    leaf = blocks[0]
    not_before, not_after = certificate_dates(leaf)
    now = datetime.now(timezone.utc)
    days = int((not_after - now).total_seconds() // 86400)
    state = (
        "expired"
        if days < 0
        else "critical"
        if days < 7
        else "expiring"
        if days < 21
        else "valid"
    )
    subject = certificate_name(leaf, "subject")
    common_name_match = re.search(r"CN=([^,]*)", subject)
    serial = _x509_text(leaf, "-serial").strip().split("=", 1)[-1].strip()
    fingerprint = _x509_text(leaf, "-fingerprint", "-sha256").strip().split("=", 1)[-1].strip()
    return {
        "hostname": hostname,
        "subject": subject,
        "issuer": certificate_name(leaf, "issuer"),
        "commonName": common_name_match.group(1) if common_name_match else None,
        "sans": san_dns_names(leaf),
        "notBefore": _iso(not_before),
        "notAfter": _iso(not_after),
        "daysRemaining": days,
        "state": state,
        "serial": serial,
        "fingerprintSha256": fingerprint,
        "chainLength": len(blocks),
    }


def validate_pair(
    certificate: bytes, private_key: bytes, chain: bytes, hostname: str
) -> dict:
    """Valide et normalise une paire candidate.

    Retourne {'summary', 'fullchain', 'key'} — rien n'est installé ici.
    """
    if not certificate:
        raise CertificateError("Certificat manquant.")
    if not private_key:
        raise CertificateError("Clé privée manquante.")
    if not hostname:
        raise CertificateError("Nom d'hôte cible non configuré.")
    blocks = certificate_blocks(certificate)
    if not blocks:
        raise CertificateError("Le certificat doit être au format PEM (BEGIN CERTIFICATE).")
    leaf = normalize_certificate(blocks[0])
    extra = [normalize_certificate(block) for block in blocks[1:]]
    if chain:
        chain_blocks = certificate_blocks(chain)
        if not chain_blocks:
            raise CertificateError("La chaîne fournie ne contient aucun certificat PEM.")
        extra.extend(normalize_certificate(block) for block in chain_blocks)

    validate_dates(leaf, "feuille")
    if not san_dns_names(leaf):
        raise CertificateError("Le certificat doit contenir au moins un SAN DNS.")
    check_hostname(leaf, hostname)
    if public_key_from_certificate(leaf) != public_key_from_private_key(private_key):
        raise CertificateError("La clé privée ne correspond pas au certificat.")
    ordered_chain = validate_chain(leaf, extra)
    key_pem = normalize_private_key(private_key)
    fullchain = leaf + b"".join(ordered_chain)

    with tempfile.TemporaryDirectory(prefix="hub-tls-") as temporary:
        directory = Path(temporary)
        fullchain_path = directory / "fullchain.pem"
        key_path = directory / "privkey.pem"
        fullchain_path.write_bytes(fullchain)
        key_path.write_bytes(key_pem)
        os.chmod(key_path, 0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            context.load_cert_chain(fullchain_path, key_path)
        except ssl.SSLError as error:
            raise CertificateError(
                "La paire normalisée n'a pas pu être chargée comme configuration TLS."
            ) from error

    return {"summary": build_summary(fullchain, hostname), "fullchain": fullchain, "key": key_pem}


# --- Activation atomique -----------------------------------------------------


def _generation_patterns(output_dir: Path) -> tuple[re.Pattern, re.Pattern]:
    name = re.escape(output_dir.name)
    return (
        re.compile(rf"\.{name}-[0-9a-f]{{16}}"),
        re.compile(rf"\.{name}-link-[0-9a-f]{{16}}"),
    )


def current_generation(output_dir: Path) -> str | None:
    """Nom de la génération active, None si aucune, erreur si lien non géré."""
    output_dir = Path(output_dir)
    active_pattern, _ = _generation_patterns(output_dir)
    if output_dir.is_symlink():
        target = os.readlink(output_dir)
        if Path(target).is_absolute() or not active_pattern.fullmatch(target):
            raise CertificateError("Le lien actif existant n'est pas géré par Hub.")
        previous = output_dir.parent / target
        if previous.is_symlink() or not previous.is_dir():
            raise CertificateError("La génération TLS active n'est pas un répertoire géré valide.")
        return target
    if output_dir.exists():
        raise CertificateError(
            f"Le chemin actif existe et n'est pas un lien géré : {output_dir}"
        )
    return None


def write_durable(path: Path, data: bytes, mode: int) -> None:
    """Écriture durable avec permissions exactes, indépendantes de l'umask du processus."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, mode)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def activate(output_dir: Path, fullchain: bytes, key_pem: bytes) -> str:
    """Écrit une nouvelle génération et bascule le lien actif. Retourne son nom."""
    output_dir = Path(output_dir)
    parent = output_dir.parent
    # Refuse un chemin existant qui ne serait pas un lien géré par Hub.
    current_generation(output_dir)
    _, link_pattern = _generation_patterns(output_dir)
    version_dir = parent / f".{output_dir.name}-{secrets.token_hex(8)}"
    temporary_link = parent / f".{output_dir.name}-link-{secrets.token_hex(8)}"

    for candidate in list(parent.iterdir()):
        if link_pattern.fullmatch(candidate.name) and candidate.is_symlink():
            candidate.unlink(missing_ok=True)

    version_dir.mkdir(mode=0o700)
    os.chmod(version_dir, 0o700)
    try:
        write_durable(version_dir / "fullchain.pem", fullchain, 0o644)
        write_durable(version_dir / "privkey.pem", key_pem, 0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(version_dir / "fullchain.pem", version_dir / "privkey.pem")
        fsync_directory(version_dir)
        temporary_link.symlink_to(version_dir.name, target_is_directory=True)
        os.replace(temporary_link, output_dir)
        fsync_directory(parent)
        return version_dir.name
    except BaseException:
        temporary_link.unlink(missing_ok=True)
        shutil.rmtree(version_dir, ignore_errors=True)
        raise


def restore(output_dir: Path, previous: str | None) -> None:
    """Rebascule le lien actif sur la génération précédente (ou le retire)."""
    output_dir = Path(output_dir)
    if previous is None:
        if output_dir.is_symlink():
            output_dir.unlink()
            fsync_directory(output_dir.parent)
        return
    temporary_link = output_dir.parent / f".{output_dir.name}-link-{secrets.token_hex(8)}"
    temporary_link.symlink_to(previous, target_is_directory=True)
    os.replace(temporary_link, output_dir)
    fsync_directory(output_dir.parent)


def cleanup_generation(parent: Path, name: str | None) -> None:
    if not name:
        return
    target = Path(parent) / name
    try:
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
    except OSError:
        pass


def active_summary(output_dir: Path, hostname: str) -> dict | None:
    fullchain = Path(output_dir) / "fullchain.pem"
    if not fullchain.is_file():
        return None
    return build_summary(fullchain.read_bytes(), hostname)
