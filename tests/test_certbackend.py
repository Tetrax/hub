"""Sélection du backend de gestion des certificats (helper / proxy / none).

Un seul code applicatif, trois backends : ces tests verrouillent le choix, les
messages d'erreur et le fait que le mode par défaut reste le helper root du VPS.
"""

from __future__ import annotations

import pytest

from app.certbackend import CertBackendError, DisabledBackend, HelperBackend, get_backend
from app.certlocal import LocalTlsBackend


def with_config(app, **values):
    return app.config | values


def test_standalone_configuration_enables_the_local_backend(app):
    """Le compose standalone définit HUB_CERT_BACKEND=local et les chemins TLS."""
    compose = (
        __import__("pathlib").Path(__file__).resolve().parents[1] / "compose.standalone.yaml"
    ).read_text(encoding="utf-8")
    assert "HUB_CERT_BACKEND: local" in compose
    assert "HUB_TLS_CERT: /certs/active/fullchain.pem" in compose
    assert "HUB_TLS_KEY: /certs/active/privkey.pem" in compose


def test_default_backend_is_the_root_helper(app):
    with app.app_context():
        assert isinstance(get_backend(), HelperBackend)
        assert get_backend().label == "helper"


@pytest.mark.parametrize("value", ["local", "direct", "self"])
def test_local_backend_is_selected_and_wired_from_configuration(app, value):
    with app.app_context():
        app.config.update(
            {
                "CERT_BACKEND": value,
                "CERTS_DIR": "/certs",
                "TLS_HOSTNAME": "hub.intra.example",
                "TLS_BIND_PORT": 8443,
                "GUNICORN_PIDFILE": "/tmp/gunicorn.pid",
            }
        )
        backend = get_backend()
    assert isinstance(backend, LocalTlsBackend)
    assert backend.label == "local"
    assert backend.hostname == "hub.intra.example"
    assert backend.certs_dir.as_posix() == "/certs"
    assert backend.internal_port == 8443
    assert backend.internal_host == "127.0.0.1"


@pytest.mark.parametrize("value", ["none", "disabled", "external", "NONE"])
def test_disabled_backend_is_selected_for_external_tls(app, value):
    with app.app_context():
        app.config.update({"CERT_BACKEND": value})
        backend = get_backend()
    assert isinstance(backend, DisabledBackend)


def test_disabled_backend_explains_why_actions_are_refused(app):
    with app.app_context():
        app.config.update({"CERT_BACKEND": "none"})
        backend = get_backend()
        status = backend.get_status()
        assert status["disabled"] is True
        assert status["present"] is False
        assert status["backend"] == "none"
        with pytest.raises(CertBackendError) as error:
            backend.validate_certificate(b"", b"", b"")
        assert "désactivée" in str(error.value)
        with pytest.raises(CertBackendError):
            backend.activate_certificate("ticket")


def test_unknown_backend_value_falls_back_to_helper(app):
    with app.app_context():
        app.config.update({"CERT_BACKEND": "inconnu"})
        assert isinstance(get_backend(), HelperBackend)


def test_helper_backend_wraps_transport_errors(app, tmp_path):
    with app.app_context():
        app.config.update({"CERT_HELPER_SOCKET": str(tmp_path / "absent.sock")})
        backend = get_backend()
        with pytest.raises(CertBackendError):
            backend.get_status()
        with pytest.raises(CertBackendError):
            backend.validate_certificate(b"cert", b"key", b"")
        with pytest.raises(CertBackendError):
            backend.activate_certificate("ticket")
