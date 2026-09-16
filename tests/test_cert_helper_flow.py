"""Processeur du helper : validate → activate, ticket à usage unique, rollback."""

from __future__ import annotations

import base64
import json
import os
import time

import pytest

import hub_cert_helper
import hub_certctl
import hub_cert_protocol as protocol

from conftest import FakeNginx, leaf_certificate


def payload_for(certificate: bytes, key: bytes, chain: bytes = b"") -> dict:
    return {
        "certificateBase64": base64.b64encode(certificate).decode("ascii"),
        "privateKeyBase64": base64.b64encode(key).decode("ascii"),
        "chainBase64": base64.b64encode(chain).decode("ascii"),
    }


def make_processor(tmp_path, nginx=None):
    staging = tmp_path / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    return hub_cert_helper.CertHelperProcessor(
        hostname="hub.valdev.me",
        output_dir=tmp_path / "active",
        staging_dir=staging,
        allowed_uid=os.getuid(),
        allowed_gid=os.getgid(),
        nginx=nginx,
    )


def test_validate_returns_ticket_and_stores_pair(tmp_path):
    processor = make_processor(tmp_path)
    cert_pem, key_pem = leaf_certificate()
    result = processor.validate(payload_for(cert_pem, key_pem))
    assert result["ok"] is True
    assert len(result["ticket"]) >= 43
    assert result["summary"]["sans"] == ["hub.valdev.me"]
    staging_entries = [entry for entry in processor.staging_dir.iterdir() if entry.is_dir()]
    assert len(staging_entries) == 1
    entry = staging_entries[0]
    assert (entry / "fullchain.pem").read_bytes() == cert_pem
    key_mode = (entry / "privkey.pem").stat().st_mode & 0o777
    assert key_mode == 0o600
    meta = json.loads((entry / "meta.json").read_text())
    assert meta["hostname"] == "hub.valdev.me"
    assert meta["expiresAtEpoch"] > time.time()


def test_validate_rejects_invalid_payload(tmp_path):
    processor = make_processor(tmp_path)
    with pytest.raises(protocol.ProtocolError):
        processor.validate({"certificateBase64": "x"})
    with pytest.raises(protocol.ProtocolError):
        processor.validate({"certificateBase64": "!!", "privateKeyBase64": "", "chainBase64": ""})
    oversized = "A" * (protocol.MAX_REQUEST_BYTES)
    with pytest.raises(protocol.ProtocolError, match="trop volumineux"):
        processor.validate(
            {"certificateBase64": oversized, "privateKeyBase64": "", "chainBase64": ""}
        )


def test_activate_installs_and_consumes_ticket(tmp_path):
    nginx = FakeNginx()
    processor = make_processor(tmp_path, nginx)
    cert_pem, key_pem = leaf_certificate()
    ticket = processor.validate(payload_for(cert_pem, key_pem))["ticket"]
    result = processor.activate(ticket)
    assert result["ok"] is True
    assert result["previous"] is None
    assert (processor.output_dir / "fullchain.pem").read_bytes() == cert_pem
    assert nginx.calls == ["test_config", "test_config", "reload", "verify_served"]
    assert not any(entry.is_dir() for entry in processor.staging_dir.iterdir())
    with pytest.raises(protocol.ProtocolError, match="introuvable"):
        processor.activate(ticket)


def test_activate_rejects_bad_ticket_format(tmp_path):
    processor = make_processor(tmp_path)
    with pytest.raises(protocol.ProtocolError, match="Ticket"):
        processor.activate("pas-un-ticket")


def test_activate_expired_ticket(tmp_path):
    processor = make_processor(tmp_path, FakeNginx())
    cert_pem, key_pem = leaf_certificate()
    ticket = processor.validate(payload_for(cert_pem, key_pem))["ticket"]
    entry = next(e for e in processor.staging_dir.iterdir() if e.is_dir())
    meta = json.loads((entry / "meta.json").read_text())
    meta["expiresAtEpoch"] = time.time() - 10
    (entry / "meta.json").write_text(json.dumps(meta))
    with pytest.raises(protocol.ProtocolError, match="introuvable ou expirée"):
        processor.activate(ticket)


def test_activate_rolls_back_when_post_check_fails(tmp_path):
    nginx = FakeNginx()
    processor = make_processor(tmp_path, nginx)
    first_pem, first_key = leaf_certificate()
    first_ticket = processor.validate(payload_for(first_pem, first_key))["ticket"]
    processor.activate(first_ticket)
    # la paire suivante échouera au `nginx -t` d'après-bascule
    nginx.fail_test_at = nginx.test_count + 2
    second_pem, second_key = leaf_certificate()
    second_ticket = processor.validate(payload_for(second_pem, second_key))["ticket"]
    with pytest.raises(hub_cert_helper.CertificateReloadError):
        processor.activate(second_ticket)
    assert (processor.output_dir / "fullchain.pem").read_bytes() == first_pem
    generations = [
        entry.name
        for entry in processor.output_dir.parent.iterdir()
        if entry.is_dir() and entry.name.startswith(".active-")
    ]
    assert len(generations) == 1  # la génération échouée a été supprimée


def test_activate_rolls_back_on_served_mismatch(tmp_path):
    nginx = FakeNginx()
    processor = make_processor(tmp_path, nginx)
    first_pem, first_key = leaf_certificate()
    processor.activate(processor.validate(payload_for(first_pem, first_key))["ticket"])
    nginx.served_mismatch = True
    second_pem, second_key = leaf_certificate()
    ticket = processor.validate(payload_for(second_pem, second_key))["ticket"]
    with pytest.raises(hub_cert_helper.CertificateReloadError, match="ne correspond pas"):
        processor.activate(ticket)
    assert (processor.output_dir / "fullchain.pem").read_bytes() == first_pem


def test_install_without_reload(tmp_path):
    processor = make_processor(tmp_path, None)
    cert_pem, key_pem = leaf_certificate()
    result = hub_certctl.validate_pair(cert_pem, key_pem, b"", "hub.valdev.me")
    installed = processor.install(result["fullchain"], result["key"], result["summary"])
    assert installed["previous"] is None
    assert (processor.output_dir / "fullchain.pem").read_bytes() == cert_pem


def test_status_reports_absence_then_presence(tmp_path):
    nginx = FakeNginx()
    processor = make_processor(tmp_path, nginx)
    status = processor.status()
    assert status["ok"] is True and status["present"] is False
    cert_pem, key_pem = leaf_certificate()
    processor.activate(processor.validate(payload_for(cert_pem, key_pem))["ticket"])
    status = processor.status()
    assert status["present"] is True
    assert status["certificate"]["hostname"] == "hub.valdev.me"


def test_process_authorization(tmp_path):
    processor = make_processor(tmp_path, FakeNginx())
    with pytest.raises(hub_cert_helper.HelperAuthorizationError):
        processor.process(
            {"version": 1, "action": "status"}, peer_uid=12345, peer_gid=12345
        )
    with pytest.raises(protocol.ProtocolError):
        processor.process(
            {"version": 1, "action": "interdit"}, peer_uid=os.getuid(), peer_gid=os.getgid()
        )
    with pytest.raises(protocol.ProtocolError, match="Version"):
        processor.process({"version": 99, "action": "ping"}, peer_uid=0, peer_gid=0)
    assert processor.process({"version": 1, "action": "ping"}, peer_uid=0, peer_gid=0)["ok"] is True
