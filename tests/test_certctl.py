"""Validation et activation des certificats (helper/hub_certctl.py)."""

from __future__ import annotations

import os
import ssl
from pathlib import Path

import pytest

import hub_certctl

from conftest import leaf_certificate, chain_certificates, make_key, private_key_pem


def test_validate_pair_ok():
    cert_pem, key_pem = leaf_certificate(days_after=365)
    result = hub_certctl.validate_pair(cert_pem, key_pem, b"", "hub.valdev.me")
    summary = result["summary"]
    assert summary["hostname"] == "hub.valdev.me"
    assert summary["sans"] == ["hub.valdev.me"]
    assert summary["state"] == "valid"
    assert 300 <= summary["daysRemaining"] <= 370
    assert summary["chainLength"] == 1
    assert len(summary["fingerprintSha256"].split(":")) == 32
    assert result["fullchain"].startswith(b"-----BEGIN CERTIFICATE-----")
    assert b"PRIVATE KEY" in result["key"]


def test_validate_pair_expiring_state():
    cert_pem, key_pem = leaf_certificate(days_after=10)
    result = hub_certctl.validate_pair(cert_pem, key_pem, b"", "hub.valdev.me")
    assert result["summary"]["state"] == "expiring"
    assert result["summary"]["daysRemaining"] < 21


def test_validate_pair_expired():
    cert_pem, key_pem = leaf_certificate(days_before=-10, days_after=-1)
    with pytest.raises(hub_certctl.CertificateError, match="expiré"):
        hub_certctl.validate_pair(cert_pem, key_pem, b"", "hub.valdev.me")


def test_validate_pair_not_yet_valid():
    cert_pem, key_pem = leaf_certificate(days_before=2, days_after=365)
    with pytest.raises(hub_certctl.CertificateError, match="pas encore valide"):
        hub_certctl.validate_pair(cert_pem, key_pem, b"", "hub.valdev.me")


def test_validate_pair_wrong_hostname():
    cert_pem, key_pem = leaf_certificate(cn="other.example.com", sans=("other.example.com",))
    with pytest.raises(hub_certctl.CertificateError, match="ne couvre pas"):
        hub_certctl.validate_pair(cert_pem, key_pem, b"", "hub.valdev.me")


def test_validate_pair_missing_san():
    cert_pem, key_pem = leaf_certificate(sans=None)
    with pytest.raises(hub_certctl.CertificateError, match="SAN"):
        hub_certctl.validate_pair(cert_pem, key_pem, b"", "hub.valdev.me")


def test_validate_pair_key_mismatch():
    cert_pem, _ = leaf_certificate()
    other_pem = private_key_pem(make_key())
    with pytest.raises(hub_certctl.CertificateError, match="ne correspond pas"):
        hub_certctl.validate_pair(cert_pem, other_pem, b"", "hub.valdev.me")


def test_validate_pair_not_pem():
    with pytest.raises(hub_certctl.CertificateError, match="format PEM"):
        hub_certctl.validate_pair(b"pas un certificat", b"pas une cle", b"", "hub.valdev.me")


def test_validate_pair_empty_inputs():
    with pytest.raises(hub_certctl.CertificateError, match="Certificat manquant"):
        hub_certctl.validate_pair(b"", b"", b"", "hub.valdev.me")
    cert_pem, _ = leaf_certificate()
    with pytest.raises(hub_certctl.CertificateError, match="Clé privée manquante"):
        hub_certctl.validate_pair(cert_pem, b"", b"", "hub.valdev.me")


def test_validate_pair_with_chain():
    leaf_pem, leaf_key_pem, intermediate_pem, _root_pem = chain_certificates()
    result = hub_certctl.validate_pair(
        leaf_pem, leaf_key_pem, intermediate_pem, "hub.valdev.me"
    )
    assert result["summary"]["chainLength"] == 2
    assert result["fullchain"].count(b"BEGIN CERTIFICATE") == 2


def test_validate_pair_chain_with_root():
    leaf_pem, leaf_key_pem, intermediate_pem, root_pem = chain_certificates()
    result = hub_certctl.validate_pair(
        leaf_pem, leaf_key_pem, intermediate_pem + root_pem, "hub.valdev.me"
    )
    assert result["summary"]["chainLength"] == 3
    assert result["fullchain"].endswith(root_pem)


def test_validate_pair_wrong_chain_rejected():
    leaf_pem, leaf_key_pem, _intermediate_pem, _root_pem = chain_certificates()
    other_pem, _ = leaf_certificate(cn="Autre CA", sans=None)
    with pytest.raises(hub_certctl.CertificateError, match="chaîne"):
        hub_certctl.validate_pair(leaf_pem, leaf_key_pem, other_pem, "hub.valdev.me")


def test_validate_pair_fullchain_in_certificate_file():
    leaf_pem, leaf_key_pem, intermediate_pem, _root = chain_certificates()
    result = hub_certctl.validate_pair(leaf_pem + intermediate_pem, leaf_key_pem, b"", "hub.valdev.me")
    assert result["summary"]["chainLength"] == 2


# --- Activation atomique -------------------------------------------------------


def test_activate_creates_generation_and_symlink(tmp_path):
    output = tmp_path / "certs" / "active"
    (tmp_path / "certs").mkdir()
    cert_pem, key_pem = leaf_certificate()
    generation = hub_certctl.activate(output, cert_pem, key_pem)
    assert output.is_symlink()
    assert os.readlink(output) == generation
    assert (output / "fullchain.pem").read_bytes() == cert_pem
    mode = (output / "privkey.pem").stat().st_mode & 0o777
    assert mode == 0o600
    chain_mode = (output / "fullchain.pem").stat().st_mode & 0o777
    assert chain_mode == 0o644
    # la paire est chargeable telle quelle
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(output / "fullchain.pem", output / "privkey.pem")
    assert hub_certctl.current_generation(output) == generation


def test_activate_replaces_and_keeps_previous(tmp_path):
    output = tmp_path / "certs" / "active"
    (tmp_path / "certs").mkdir()
    first_pem, first_key = leaf_certificate()
    first_gen = hub_certctl.activate(output, first_pem, first_key)
    second_pem, second_key = leaf_certificate(cn="hub.valdev.me")
    second_gen = hub_certctl.activate(output, second_pem, second_key)
    assert second_gen != first_gen
    assert hub_certctl.current_generation(output) == second_gen
    assert (tmp_path / "certs" / first_gen).is_dir()  # conservée pour rollback


def test_restore_previous_generation(tmp_path):
    output = tmp_path / "certs" / "active"
    (tmp_path / "certs").mkdir()
    first_pem, first_key = leaf_certificate()
    first_gen = hub_certctl.activate(output, first_pem, first_key)
    second_pem, second_key = leaf_certificate()
    hub_certctl.activate(output, second_pem, second_key)
    hub_certctl.restore(output, first_gen)
    assert hub_certctl.current_generation(output) == first_gen
    assert (output / "fullchain.pem").read_bytes() == first_pem


def test_restore_removes_link_when_no_previous(tmp_path):
    output = tmp_path / "certs" / "active"
    (tmp_path / "certs").mkdir()
    cert_pem, key_pem = leaf_certificate()
    hub_certctl.activate(output, cert_pem, key_pem)
    hub_certctl.restore(output, None)
    assert not output.exists()
    assert not output.is_symlink()


def test_activate_rejects_unmanaged_existing_path(tmp_path):
    output = tmp_path / "active"
    output.mkdir()
    cert_pem, key_pem = leaf_certificate()
    with pytest.raises(hub_certctl.CertificateError, match="n'est pas un lien géré"):
        hub_certctl.activate(output, cert_pem, key_pem)
    with pytest.raises(hub_certctl.CertificateError, match="n'est pas un lien géré"):
        hub_certctl.current_generation(output)


def test_cleanup_generation(tmp_path):
    output = tmp_path / "certs" / "active"
    (tmp_path / "certs").mkdir()
    cert_pem, key_pem = leaf_certificate()
    first_gen = hub_certctl.activate(output, cert_pem, key_pem)
    second_pem, second_key = leaf_certificate()
    hub_certctl.activate(output, second_pem, second_key)
    hub_certctl.cleanup_generation(output.parent, first_gen)
    assert not (tmp_path / "certs" / first_gen).exists()


def test_active_summary(tmp_path):
    output = tmp_path / "certs" / "active"
    (tmp_path / "certs").mkdir()
    assert hub_certctl.active_summary(output, "hub.valdev.me") is None
    cert_pem, key_pem = leaf_certificate()
    hub_certctl.activate(output, cert_pem, key_pem)
    summary = hub_certctl.active_summary(output, "hub.valdev.me")
    assert summary is not None and summary["hostname"] == "hub.valdev.me"
