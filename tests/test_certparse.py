"""Bundles PKCS#12/PFX et normalisation PEM/DER : extraction en mémoire uniquement."""

from __future__ import annotations

import tempfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
    pkcs12,
)

from app import certparse
from conftest import chain_certificates, leaf_certificate, make_certificate


def build_pfx(
    *,
    leaf_pem: bytes,
    key_pem: bytes | None,
    cas: list[bytes] | None = None,
    password: str = "",
    name: bytes = b"SNS Hub test",
) -> bytes:
    """Construit un bundle PKCS#12 de test (mot de passe optionnel)."""
    key = load_pem_private_key(key_pem, password=None) if key_pem else None
    leaf = x509.load_pem_x509_certificate(leaf_pem)
    extras = [x509.load_pem_x509_certificate(pem) for pem in (cas or [])]
    encryption = (
        BestAvailableEncryption(password.encode("utf-8")) if password else NoEncryption()
    )
    return pkcs12.serialize_key_and_certificates(
        name=name,
        key=key,  # type: ignore[arg-type]  # clé RSA de test : sous-type accepté à l'exécution
        cert=leaf,
        cas=extras or None,
        encryption_algorithm=encryption,
    )


def fingerprint(pem: bytes) -> bytes:
    return x509.load_pem_x509_certificate(pem).fingerprint(hashes.SHA256())


@pytest.fixture()
def chained() -> dict:
    leaf_pem, key_pem, intermediate_pem, root_pem = chain_certificates()
    return {
        "leaf": leaf_pem,
        "key": key_pem,
        "intermediate": intermediate_pem,
        "root": root_pem,
    }


# --- Extraction PKCS#12 --------------------------------------------------------


def test_pkcs12_with_password(chained):
    bundle = build_pfx(
        leaf_pem=chained["leaf"],
        key_pem=chained["key"],
        cas=[chained["intermediate"], chained["root"]],
        password="mot-de-passe-test",
    )
    leaf, key, chain = certparse.extract_pkcs12(bundle, "mot-de-passe-test")
    assert fingerprint(leaf) == fingerprint(chained["leaf"])
    assert b"PRIVATE KEY-----" in key
    # La feuille correspond bien à la clé extraite.
    assert load_pem_private_key(key, password=None).public_key() == x509.load_pem_x509_certificate(
        leaf
    ).public_key()
    # La chaîne contient l'intermédiaire, jamais la racine.
    assert fingerprint(chain) == fingerprint(chained["intermediate"])
    assert fingerprint(chained["root"]) != fingerprint(chain)


def test_pkcs12_without_password(chained):
    bundle = build_pfx(leaf_pem=chained["leaf"], key_pem=chained["key"])
    leaf, key, chain = certparse.extract_pkcs12(bundle, "")
    assert fingerprint(leaf) == fingerprint(chained["leaf"])
    assert chain == b""


def test_pkcs12_password_ignored_when_absent(chained):
    """Un mot de passe fourni pour un bundle non protégé ne doit pas empêcher l'import."""
    bundle = build_pfx(leaf_pem=chained["leaf"], key_pem=chained["key"])
    leaf, _, _ = certparse.extract_pkcs12(bundle, "mot-de-passe-inutile")
    assert fingerprint(leaf) == fingerprint(chained["leaf"])


def test_pkcs12_wrong_password_message_is_clean(chained):
    bundle = build_pfx(leaf_pem=chained["leaf"], key_pem=chained["key"], password="vrai")
    with pytest.raises(certparse.CertificateInputError) as error:
        certparse.extract_pkcs12(bundle, "faux")
    assert str(error.value) == "Impossible d'ouvrir le fichier PKCS#12. Vérifiez le mot de passe."
    assert error.value.code == "unreadable"
    # Aucun détail technique, aucun chemin, aucun secret dans le message.
    for forbidden in ("openssl", "/", "Traceback", "vrai", "faux"):
        assert forbidden not in str(error.value)


def test_pkcs12_corrupted_file(chained):
    with pytest.raises(certparse.CertificateInputError) as error:
        certparse.extract_pkcs12(b"\x30\x82\x01\x00" + b"\x00" * 64, "")
    assert error.value.code == "unreadable"


def test_pkcs12_pem_renamed(chained):
    with pytest.raises(certparse.CertificateInputError) as error:
        certparse.extract_pkcs12(chained["leaf"], "")
    assert error.value.code == "not_pkcs12"
    assert "PEM" in str(error.value)


def test_pkcs12_without_private_key(chained):
    bundle = build_pfx(leaf_pem=chained["leaf"], key_pem=None, cas=[chained["intermediate"]])
    with pytest.raises(certparse.CertificateInputError) as error:
        certparse.extract_pkcs12(bundle, "")
    assert error.value.code == "no_key"
    assert "clé privée" in str(error.value)


def test_pkcs12_too_large(chained):
    payload = b"\x00" * (certparse.MAX_BUNDLE_BYTES + 1)
    with pytest.raises(certparse.CertificateInputError) as error:
        certparse.extract_pkcs12(payload, "")
    assert error.value.code == "too_large"


def test_pkcs12_empty_bundle():
    with pytest.raises(certparse.CertificateInputError) as error:
        certparse.extract_pkcs12(b"", "")
    assert error.value.code == "empty"


def test_chain_is_rebuilt_in_order_and_root_excluded():
    """Deux intermédiaires fournis dans le désordre + racine : ordre reconstruit."""
    root_pem, root_key = make_certificate(cn="Racine test", sans=None, is_ca=True)
    root_cert = x509.load_pem_x509_certificate(root_pem)
    intermediate_one_pem, intermediate_one_key = make_certificate(
        cn="Intermédiaire 1", sans=None, is_ca=True, issuer_cert=root_cert, issuer_key=root_key
    )
    intermediate_one_cert = x509.load_pem_x509_certificate(intermediate_one_pem)
    intermediate_two_pem, intermediate_two_key = make_certificate(
        cn="Intermédiaire 2",
        sans=None,
        is_ca=True,
        issuer_cert=intermediate_one_cert,
        issuer_key=intermediate_one_key,
    )
    intermediate_two_cert = x509.load_pem_x509_certificate(intermediate_two_pem)
    leaf_pem, leaf_key = make_certificate(
        cn="hub.valdev.me", issuer_cert=intermediate_two_cert, issuer_key=intermediate_two_key
    )
    bundle = build_pfx(
        leaf_pem=leaf_pem,
        key_pem=leaf_key.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        ),
        cas=[intermediate_one_pem, root_pem, intermediate_two_pem],
    )
    _, _, chain = certparse.extract_pkcs12(bundle, "")
    blocks = chain.split(b"-----END CERTIFICATE-----")
    names = [
        x509.load_pem_x509_certificate(block + b"-----END CERTIFICATE-----\n").subject.rfc4514_string()
        for block in blocks
        if b"-----BEGIN CERTIFICATE-----" in block
    ]
    assert names == ["CN=Intermédiaire 2", "CN=Intermédiaire 1"]
    assert all("Racine" not in name for name in names)


def test_chain_ignores_unrelated_certificate(chained):
    """Un certificat sans lien avec la feuille n'est jamais embarqué dans la chaîne."""
    unrelated_pem, _ = make_certificate(cn="autre.domaine.test")
    bundle = build_pfx(
        leaf_pem=chained["leaf"],
        key_pem=chained["key"],
        cas=[chained["intermediate"], unrelated_pem],
    )
    _, _, chain = certparse.extract_pkcs12(bundle, "")
    assert fingerprint(chain) == fingerprint(chained["intermediate"])
    assert b"autre.domaine.test" not in chain


def test_chain_ignores_duplicate_of_leaf(chained):
    bundle = build_pfx(leaf_pem=chained["leaf"], key_pem=chained["key"], cas=[chained["leaf"]])
    _, _, chain = certparse.extract_pkcs12(bundle, "")
    assert chain == b""


def test_extraction_uses_no_temporary_file(chained, monkeypatch: pytest.MonkeyPatch):
    """Tout est traité en mémoire : aucun fichier temporaire, aucune écriture disque."""

    def forbidden(*args, **kwargs):  # noqa: ARG001
        raise AssertionError("aucun fichier temporaire ne doit être créé")

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", forbidden)
    monkeypatch.setattr(tempfile, "TemporaryDirectory", forbidden)
    monkeypatch.setattr(tempfile, "mkstemp", forbidden)
    monkeypatch.setattr(tempfile, "mkdtemp", forbidden)
    bundle = build_pfx(
        leaf_pem=chained["leaf"],
        key_pem=chained["key"],
        cas=[chained["intermediate"]],
        password="secret",
    )
    leaf, key, chain = certparse.extract_pkcs12(bundle, "secret")
    assert fingerprint(leaf) == fingerprint(chained["leaf"])
    assert chain


# --- Normalisation PEM / DER ---------------------------------------------------


def test_normalize_certificate_pem_passthrough(chained):
    assert certparse.normalize_certificate(chained["leaf"]) == chained["leaf"]


def test_normalize_certificate_der(chained):
    der = x509.load_pem_x509_certificate(chained["leaf"]).public_bytes(Encoding.DER)
    converted = certparse.normalize_certificate(der)
    assert converted.startswith(b"-----BEGIN CERTIFICATE-----")
    assert fingerprint(converted) == fingerprint(chained["leaf"])


def test_normalize_certificate_unreadable():
    with pytest.raises(certparse.CertificateInputError) as error:
        certparse.normalize_certificate(b"pas un certificat")
    assert error.value.code == "unreadable_certificate"


def test_normalize_private_key_pem_passthrough(chained):
    assert certparse.normalize_private_key(chained["key"]) == chained["key"]


def test_normalize_private_key_der_pkcs8(chained):
    key = load_pem_private_key(chained["key"], password=None)
    der = key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    converted = certparse.normalize_private_key(der)
    assert b"PRIVATE KEY-----" in converted
    assert load_pem_private_key(converted, password=None).public_key() == key.public_key()


def test_normalize_private_key_der_pkcs1(chained):
    key = load_pem_private_key(chained["key"], password=None)
    der = key.private_bytes(Encoding.DER, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    converted = certparse.normalize_private_key(der)
    assert load_pem_private_key(converted, password=None).public_key() == key.public_key()


def test_normalize_private_key_rejects_encrypted_pem(chained):
    key = load_pem_private_key(chained["key"], password=None)
    encrypted = key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b"mot-de-passe")
    )
    with pytest.raises(certparse.CertificateInputError) as error:
        certparse.normalize_private_key(encrypted)
    assert error.value.code == "encrypted_key"
    assert "chiffrée" in str(error.value)


def test_normalize_private_key_unreadable():
    with pytest.raises(certparse.CertificateInputError) as error:
        certparse.normalize_private_key(b"pas une cle")
    assert error.value.code == "unreadable_key"


def test_leaf_certificate_without_chain_is_accepted():
    leaf_pem, key_pem = leaf_certificate()
    bundle = build_pfx(leaf_pem=leaf_pem, key_pem=key_pem, password="p")
    leaf, key, chain = certparse.extract_pkcs12(bundle, "p")
    assert chain == b""
    assert fingerprint(leaf) == fingerprint(leaf_pem)
