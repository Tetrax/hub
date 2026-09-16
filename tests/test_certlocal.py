"""Backend certificat « local » du déploiement standalone (TLS direct).

Le serveur HTTPS réel est remplacé par `tests/tls_stub_server.py` : un vrai
serveur TLS qui reprend la paire courante sur SIGHUP — comme le font les workers
gunicorn redémarrés par le rechargement gracieux.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from conftest import chain_certificates, leaf_certificate

from app.certbackend import CertBackendError
from app.certlocal import LocalTlsBackend, bootstrap_certificate

STUB = Path(__file__).resolve().parent / "tls_stub_server.py"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class StubServer:
    """Serveur HTTPS de test : sert une paire sur disque, la reprend sur SIGHUP.

    Comme le serveur réel, il lit le chemin STABLE `active/fullchain.pem` : c'est
    la bascule du lien qui change la paire servie après rechargement.
    """

    def __init__(self, cert: Path, key: Path, pidfile: Path, ignore_hup: bool = False):
        self.cert = Path(cert)
        self.key = Path(key)
        self.pidfile = Path(pidfile)
        self.ignore_hup = ignore_hup
        self.port = free_port()
        self.process: subprocess.Popen | None = None

    def start(self) -> None:
        command = [
            sys.executable,
            str(STUB),
            "--cert",
            str(self.cert),
            "--key",
            str(self.key),
            "--port",
            str(self.port),
            "--pidfile",
            str(self.pidfile),
        ]
        if self.ignore_hup:
            command.append("--ignore-hup")
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            line = (self.process.stdout.readline() or "").strip() if self.process.stdout else ""
            if line.startswith("ready"):
                return
            time.sleep(0.05)
        raise RuntimeError("le serveur HTTPS de test n'a pas démarré")

    def stop(self) -> None:
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None


@pytest.fixture()
def certs_dir(tmp_path):
    """Volume de certificats avec le certificat temporaire de bootstrap."""
    certs = tmp_path / "certs"
    certs.mkdir()
    bootstrap_certificate(certs, "hub.valdev.me")
    return certs


@pytest.fixture()
def stub(certs_dir, tmp_path):
    server = StubServer(
        certs_dir / "active" / "fullchain.pem",
        certs_dir / "active" / "privkey.pem",
        tmp_path / "stub.pid",
    )
    server.start()
    yield server
    server.stop()


@pytest.fixture()
def backend(certs_dir, stub):
    return LocalTlsBackend(
        certs_dir=certs_dir,
        hostname="hub.valdev.me",
        internal_host="127.0.0.1",
        internal_port=stub.port,
        pidfile=stub.pidfile,
        reload_timeout=8,
    )


# --- Validation ---------------------------------------------------------------


def test_validate_accepts_matching_hostname_and_stages_pair(backend):
    certificate, key = leaf_certificate()
    result = backend.validate_certificate(certificate, key, b"")

    assert result["ticket"]
    assert result["summary"]["sans"] == ["hub.valdev.me"]
    staged = backend.staging_dir / result["ticket"]
    assert (staged / "privkey.pem").is_file()
    # Clé privée jamais lisible par les autres utilisateurs.
    assert (staged / "privkey.pem").stat().st_mode & 0o077 == 0


def test_validate_rejects_certificate_for_another_hostname(backend):
    certificate, key = leaf_certificate(cn="autre.example", sans=("autre.example",))
    with pytest.raises(CertBackendError) as error:
        backend.validate_certificate(certificate, key, b"")
    assert "hub.valdev.me" in str(error.value)


def test_validate_requires_hostname(tmp_path, stub):
    instance = LocalTlsBackend(certs_dir=tmp_path / "certs", hostname="", internal_port=stub.port)
    certificate, key = leaf_certificate()
    with pytest.raises(CertBackendError) as error:
        instance.validate_certificate(certificate, key, b"")
    assert "HUB_TLS_HOSTNAME" in str(error.value)


def test_activate_refuses_unknown_or_expired_ticket(backend):
    with pytest.raises(CertBackendError) as error:
        backend.activate_certificate("inconnu")
    assert "relancez la validation" in str(error.value).lower()

    certificate, key = leaf_certificate()
    ticket = backend.validate_certificate(certificate, key, b"")["ticket"]
    staged = backend.staging_dir / ticket
    os.utime(staged, (1, 1))
    with pytest.raises(CertBackendError) as error:
        backend.activate_certificate(ticket)
    assert "expirée" in str(error.value).lower()
    assert not staged.exists()


def test_validation_reports_unwritable_certs_volume(tmp_path, stub):
    certs = tmp_path / "certs-readonly"
    certs.mkdir()
    certs.chmod(0o500)
    backend = LocalTlsBackend(
        certs_dir=certs, hostname="hub.valdev.me", internal_port=stub.port, pidfile=stub.pidfile
    )
    certificate, key = leaf_certificate()
    try:
        with pytest.raises(CertBackendError) as error:
            backend.validate_certificate(certificate, key, b"")
        assert "volume" in str(error.value).lower()
    finally:
        certs.chmod(0o700)


# --- Activation ---------------------------------------------------------------


def test_activation_installs_generation_and_verifies_served_certificate(backend):
    certificate, key = leaf_certificate()
    activated = backend.activate_certificate(
        backend.validate_certificate(certificate, key, b"")["ticket"]
    )
    assert activated["ok"] is True
    assert activated["backend"] == "local"
    assert activated["servedMatches"] is True
    assert backend.active_path.is_symlink()
    assert (backend.active_path / "fullchain.pem").is_file()


def test_activation_serves_the_new_certificate_after_reload(backend):
    """Le nouveau certificat est réellement présenté après le rechargement."""
    second, second_key = leaf_certificate()
    activated = backend.activate_certificate(
        backend.validate_certificate(second, second_key, b"")["ticket"]
    )
    import hub_certctl

    served = backend._served_certificate()
    assert served is not None
    assert hub_certctl.certificate_fingerprint(served) == activated["summary"]["fingerprintSha256"]


def test_activation_cleans_previous_generation(backend):
    first, first_key = leaf_certificate()
    first_result = backend.activate_certificate(
        backend.validate_certificate(first, first_key, b"")["ticket"]
    )
    second, second_key = leaf_certificate()
    second_result = backend.activate_certificate(
        backend.validate_certificate(second, second_key, b"")["ticket"]
    )
    assert second_result["generation"] != first_result["generation"]
    assert not (backend.certs_dir / first_result["generation"]).exists()
    generations = [
        entry.name
        for entry in backend.certs_dir.iterdir()
        if entry.is_dir() and not entry.is_symlink() and entry.name != "staging"
    ]
    assert generations == [second_result["generation"]]


def test_activation_rolls_back_when_server_keeps_the_old_certificate(tmp_path):
    """Le serveur n'applique pas la nouvelle paire : rollback complet."""
    import hub_certctl

    certs = tmp_path / "certs"
    certs.mkdir()
    first, first_key = leaf_certificate()
    previous_generation = hub_certctl.activate(certs / "active", first, first_key)

    # Le serveur démarre sur la paire active puis ignore tout rechargement.
    server = StubServer(
        certs / "active" / "fullchain.pem",
        certs / "active" / "privkey.pem",
        tmp_path / "stub.pid",
        ignore_hup=True,
    )
    server.start()
    backend = LocalTlsBackend(
        certs_dir=certs,
        hostname="hub.valdev.me",
        internal_port=server.port,
        pidfile=server.pidfile,
        reload_timeout=3,
    )
    try:
        other, other_key = leaf_certificate()
        with pytest.raises(CertBackendError) as error:
            backend.activate_certificate(
                backend.validate_certificate(other, other_key, b"")["ticket"]
            )
        assert "restaurée" in str(error.value)
        # La génération précédente est toujours active, la nouvelle a disparu.
        assert (certs / previous_generation).is_dir()
        served = backend._served_certificate()
        assert served is not None
        assert hub_certctl.certificate_fingerprint(served) == hub_certctl.certificate_fingerprint(
            first
        )
        generations = [
            entry.name
            for entry in certs.iterdir()
            if entry.is_dir() and not entry.is_symlink() and entry.name != "staging"
        ]
        assert generations == [previous_generation]
    finally:
        server.stop()


def test_activation_fails_cleanly_without_pidfile(tmp_path):
    certs = tmp_path / "certs"
    certs.mkdir()
    certificate, key = leaf_certificate()
    backend = LocalTlsBackend(
        certs_dir=certs,
        hostname="hub.valdev.me",
        internal_port=free_port(),
        pidfile=tmp_path / "absent.pid",
        reload_timeout=2,
    )
    ticket = backend.validate_certificate(certificate, key, b"")["ticket"]
    with pytest.raises(CertBackendError) as error:
        backend.activate_certificate(ticket)
    assert "rechargement" in str(error.value) or "introuvable" in str(error.value)
    assert not backend.active_path.exists()


# --- État ---------------------------------------------------------------------


def test_status_reports_bootstrap_when_marker_is_present(backend):
    status = backend.get_status()
    assert status["backend"] == "local"
    assert status["present"] is True
    assert status["bootstrap"] is True
    assert status["servedMatches"] is True
    assert status["proxyReachable"] is True


def test_status_is_not_bootstrap_after_real_activation(backend):
    certificate, key = leaf_certificate()
    backend.activate_certificate(backend.validate_certificate(certificate, key, b"")["ticket"])
    status = backend.get_status()
    assert status["bootstrap"] is False
    assert status["present"] is True
    assert status["servedMatches"] is True
    assert status["certificate"]["fingerprintSha256"] == status["served"]["fingerprintSha256"]


def test_status_without_server_reports_unreachable(tmp_path):
    certs = tmp_path / "certs"
    certs.mkdir()
    backend = LocalTlsBackend(
        certs_dir=certs, hostname="hub.valdev.me", internal_port=free_port()
    )
    status = backend.get_status()
    assert status["proxyReachable"] is False
    assert status["servedMatches"] is None
    assert status["bootstrap"] is False


# --- Amorçage (bootstrap) -----------------------------------------------------


def test_bootstrap_creates_a_managed_generation_and_marker(tmp_path):
    certs = tmp_path / "certs"
    generation = bootstrap_certificate(certs, "hub.sns-security.lan")
    assert generation
    assert (certs / "active" / "fullchain.pem").is_file()
    assert (certs / "active" / "privkey.pem").is_file()
    assert (certs / ".bootstrap").is_file()
    # Couvre bien le nom demandé et la clé n'est lisible que par son propriétaire.
    assert (certs / "active" / "privkey.pem").stat().st_mode & 0o077 == 0
    backend = LocalTlsBackend(certs_dir=certs, hostname="hub.sns-security.lan", internal_port=1)
    assert backend.get_status()["bootstrap"] is True


def test_bootstrap_is_idempotent(tmp_path):
    certs = tmp_path / "certs"
    first = bootstrap_certificate(certs, "hub.sns-security.lan")
    second = bootstrap_certificate(certs, "hub.sns-security.lan")
    assert second is None  # rien à refaire tant que le bootstrap est valable
    assert (certs / first).is_dir()


def test_bootstrap_never_touches_a_real_pair(tmp_path):
    certs = tmp_path / "certs"
    certs.mkdir()
    import hub_certctl

    certificate, key = leaf_certificate()
    hub_certctl.activate(certs / "active", certificate, key)
    assert bootstrap_certificate(certs, "hub.valdev.me") is None
    assert not (certs / ".bootstrap").exists()


def test_bootstrap_is_renewed_when_expired(tmp_path):
    """Un bootstrap périmé (et lui seul) est régénéré au démarrage suivant."""
    import hub_certctl
    from conftest import make_certificate, private_key_pem

    certs = tmp_path / "certs"
    certs.mkdir()
    expired, expired_key = make_certificate(
        cn="hub.sns-security.lan", sans=("hub.sns-security.lan",), days_before=-40, days_after=-10
    )
    hub_certctl.activate(certs / "active", expired, private_key_pem(expired_key))
    (certs / ".bootstrap").write_text("temporaire\n", encoding="utf-8")

    generation = bootstrap_certificate(certs, "hub.sns-security.lan")
    assert generation
    _, not_after = hub_certctl.certificate_dates((certs / "active" / "fullchain.pem").read_bytes())
    assert not_after > __import__("datetime").datetime.now(__import__("datetime").timezone.utc)


def test_bootstrap_requires_hostname(tmp_path):
    with pytest.raises(SystemExit):
        bootstrap_certificate(tmp_path / "certs", "")


# --- Chaînes ------------------------------------------------------------------


def test_full_chain_is_served_after_activation(backend):
    leaf, leaf_key, intermediate, root = chain_certificates()
    result = backend.activate_certificate(
        backend.validate_certificate(leaf, leaf_key, intermediate + root)["ticket"]
    )
    assert result["summary"]["chainLength"] == 3
    fullchain = (backend.active_path / "fullchain.pem").read_bytes()
    assert fullchain.count(b"BEGIN CERTIFICATE") == 3


def test_private_key_permissions_in_generation(backend):
    certificate, key = leaf_certificate()
    backend.activate_certificate(backend.validate_certificate(certificate, key, b"")["ticket"])
    assert (backend.active_path / "privkey.pem").stat().st_mode & 0o077 == 0
    assert (backend.active_path / "fullchain.pem").stat().st_mode & 0o044 != 0


def test_sighup_is_used_and_process_is_not_restarted(backend, stub):  # noqa: D401
    certificate, key = leaf_certificate()
    before = stub.process.pid if stub.process else None
    backend.activate_certificate(backend.validate_certificate(certificate, key, b"")["ticket"])
    assert stub.process is not None and stub.process.poll() is None
    assert stub.process.pid == before  # même processus : rechargement, pas redémarrage


def test_pid_one_is_accepted(tmp_path, monkeypatch):
    """Dans un conteneur, gunicorn est le processus principal : PID 1 est valide."""
    certs = tmp_path / "certs"
    certs.mkdir()
    pidfile = tmp_path / "gunicorn.pid"
    pidfile.write_text("1\n", encoding="ascii")
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: sent.append((pid, sig)))
    backend = LocalTlsBackend(
        certs_dir=certs, hostname="hub.valdev.me", internal_port=1, pidfile=pidfile
    )
    backend._reload()
    assert sent == [(1, signal.SIGHUP)]


def test_signal_is_sent_to_the_pidfile_process(tmp_path, monkeypatch):
    """Le PID ciblé est celui du fichier PID (le maître du serveur)."""
    certs = tmp_path / "certs"
    certs.mkdir()
    pidfile = tmp_path / "stub.pid"
    pidfile.write_text("4242\n", encoding="ascii")
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: sent.append((pid, sig)))
    backend = LocalTlsBackend(
        certs_dir=certs, hostname="hub.valdev.me", internal_port=1, pidfile=pidfile
    )
    backend._reload()
    assert sent == [(4242, signal.SIGHUP)]


def test_import_from_outside_container_uses_helpers_module():
    """Le module partagé reste la seule implémentation de validation."""
    import hub_certctl

    assert hasattr(hub_certctl, "validate_pair")
    certificate, _ = leaf_certificate()
    assert hub_certctl.certificate_fingerprint(certificate)
