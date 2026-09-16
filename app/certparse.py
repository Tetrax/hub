"""Préparation des entrées certificat : PKCS#12/PFX, PEM, DER.

Tout est traité **en mémoire** : aucun fichier temporaire, aucune écriture disque.
Le mot de passe d'un bundle PKCS#12 est un secret éphémère : il n'est utilisé que
le temps de l'extraction, jamais journalisé, jamais renvoyé, jamais conservé.

Le résultat de ces fonctions alimente **le pipeline existant** (validation par le
helper root puis activation atomique) : rien n'est validé ni installé ici.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_der_private_key,
    pkcs12,
)

# Un bundle PKCS#12 réel pèse quelques kilo-octets ; 256 Ko laisse une marge très
# large (chaînes complètes, certificats racine inclus) tout en bornant l'entrée.
MAX_BUNDLE_BYTES = 256 * 1024
MAX_BUNDLE_CERTS = 16

PEM_CERT_MARKER = b"-----BEGIN CERTIFICATE-----"
PEM_KEY_MARKER = b"PRIVATE KEY-----"
ENCRYPTED_KEY_MARKER = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"


class CertificateInputError(ValueError):
    """Erreur destinée à l'utilisateur (message déjà propre, sans détail technique)."""

    def __init__(self, message: str, code: str = "invalid") -> None:
        super().__init__(message)
        self.code = code


def _fingerprint(certificate: x509.Certificate) -> bytes:
    return certificate.fingerprint(hashes.SHA256())


def _load_bundle(data: bytes, secret: bytes | None):
    return pkcs12.load_key_and_certificates(data, secret)


def build_chain(
    leaf: x509.Certificate, candidates: list[x509.Certificate]
) -> list[x509.Certificate]:
    """Ordonne la chaîne feuille → intermédiaires (racine auto-signée omise).

    Ne choisit jamais « le premier certificat venu » : on suit les relations
    émetteur/sujet depuis le certificat associé à la clé privée.
    """
    remaining = [cert for cert in candidates if _fingerprint(cert) != _fingerprint(leaf)]
    ordered: list[x509.Certificate] = []
    seen = {_fingerprint(leaf)}
    current = leaf
    while remaining and len(ordered) < MAX_BUNDLE_CERTS:
        matches = [cert for cert in remaining if cert.subject == current.issuer]
        if len(matches) != 1:
            break
        candidate = matches[0]
        fingerprint = _fingerprint(candidate)
        if fingerprint in seen:
            break
        if candidate.subject == candidate.issuer:
            break  # racine auto-signée : inutile dans la chaîne servie par Nginx
        ordered.append(candidate)
        seen.add(fingerprint)
        remaining.remove(candidate)
        current = candidate
    return ordered


def pem_from_certificate(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(Encoding.PEM)


def pem_from_private_key(key) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def extract_pkcs12(data: bytes, password: str = "") -> tuple[bytes, bytes, bytes]:
    """Extrait (certificat feuille, clé privée, chaîne) d'un bundle PKCS#12.

    Le certificat feuille est celui qui correspond réellement à la clé privée
    (choix fait par la bibliothèque PKCS#12, jamais « le premier certificat »).
    """
    if not data:
        raise CertificateInputError("Le fichier est vide.", "empty")
    if len(data) > MAX_BUNDLE_BYTES:
        raise CertificateInputError(
            f"Fichier trop volumineux ({MAX_BUNDLE_BYTES // 1024} Ko maximum).", "too_large"
        )
    if data.lstrip().startswith(b"-----BEGIN"):
        raise CertificateInputError(
            "Ce fichier est au format PEM : utilisez la méthode « PEM / CRT avancé ».", "not_pkcs12"
        )

    secret = password.encode("utf-8") if password else None
    try:
        key, certificate, extra_certificates = _load_bundle(data, secret)
    except UnsupportedAlgorithm:
        raise CertificateInputError(
            "Ce fichier PKCS#12 utilise un algorithme non pris en charge.", "unsupported"
        ) from None
    except (ValueError, TypeError, OSError):
        if secret is not None:
            # Un mot de passe saisi pour un bundle non protégé ne doit pas bloquer :
            # on retente sans mot de passe avant d'afficher l'erreur.
            try:
                key, certificate, extra_certificates = _load_bundle(data, None)
            except (ValueError, TypeError, OSError, UnsupportedAlgorithm):
                raise CertificateInputError(
                    "Impossible d'ouvrir le fichier PKCS#12. Vérifiez le mot de passe.",
                    "unreadable",
                ) from None
        else:
            raise CertificateInputError(
                "Impossible d'ouvrir le fichier PKCS#12. Vérifiez le mot de passe.", "unreadable"
            ) from None

    if key is None:
        raise CertificateInputError(
            "Le fichier PKCS#12 ne contient pas de clé privée.", "no_key"
        )
    if certificate is None:
        raise CertificateInputError(
            "Le fichier PKCS#12 ne contient pas de certificat.", "no_cert"
        )

    candidates = list(extra_certificates or [])
    if len(candidates) > MAX_BUNDLE_CERTS:
        raise CertificateInputError(
            "Le fichier PKCS#12 contient trop de certificats pour être traité.", "too_many_certs"
        )
    chain = build_chain(certificate, candidates)
    chain_pem = b"".join(pem_from_certificate(item) for item in chain)
    return pem_from_certificate(certificate), pem_from_private_key(key), chain_pem


def normalize_certificate(data: bytes) -> bytes:
    """PEM renvoyé tel quel ; DER converti en PEM (détection par contenu réel)."""
    if not data:
        raise CertificateInputError("Le fichier est vide.", "empty")
    if PEM_CERT_MARKER in data:
        return data
    try:
        certificate = x509.load_der_x509_certificate(data)
    except (ValueError, TypeError):
        raise CertificateInputError(
            "Certificat illisible : PEM ou DER attendu.", "unreadable_certificate"
        ) from None
    return pem_from_certificate(certificate)


def normalize_private_key(data: bytes) -> bytes:
    """PEM renvoyé tel quel ; DER (PKCS#8/PKCS#1/EC) converti en PEM."""
    if not data:
        raise CertificateInputError("Le fichier est vide.", "empty")
    if ENCRYPTED_KEY_MARKER in data:
        raise CertificateInputError(
            "La clé privée ne doit pas être chiffrée par mot de passe.", "encrypted_key"
        )
    if PEM_KEY_MARKER in data:
        return data
    try:
        key = load_der_private_key(data, password=None)
    except UnsupportedAlgorithm:
        raise CertificateInputError(
            "Ce format de clé privée n'est pas pris en charge.", "unsupported"
        ) from None
    except (ValueError, TypeError):
        raise CertificateInputError(
            "Clé privée illisible : PEM ou DER attendu.", "unreadable_key"
        ) from None
    return pem_from_private_key(key)
