"""Branding du header : libellé configurable (`HUB_BRAND_LABEL`), validé et purement visuel."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app import create_app, load_config
from app.config import BRAND_LABEL_MAX

REPO = Path(__file__).resolve().parents[1]
HEADER_RE = re.compile(r'<span class="brand-name">(.*?)</span>')

VERSIONED_FILES = ("compose.yaml", "compose.standalone.yaml", ".env.example")


def header_label(body: str) -> str:
    match = HEADER_RE.search(body)
    assert match, "libellé de marque absent du header"
    return match.group(1)


def base_config(tmp_path) -> dict:
    return {
        "DATA_DIR": tmp_path,
        "DB_PATH": tmp_path / "hub.sqlite",
        "UPLOADS_DIR": tmp_path / "uploads",
        "SECRET_KEY_FILE": tmp_path / ".secret_key",
        "TLS_HOSTNAME": "hub.valdev.me",
        "CERT_HELPER_SOCKET": str(tmp_path / "absent-helper.sock"),
        "TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
    }


@pytest.fixture()
def make_app(tmp_path, monkeypatch):
    """Fabrique l'application avec `HUB_BRAND_LABEL` posée dans l'environnement."""

    def factory(label: str | None = None, overrides: dict | None = None):
        if label is None:
            monkeypatch.delenv("HUB_BRAND_LABEL", raising=False)
        else:
            monkeypatch.setenv("HUB_BRAND_LABEL", label)
        application = create_app({**base_config(tmp_path), **(overrides or {})})
        application.config.update(TESTING=True)
        return application

    return factory


# --- Valeur par défaut et lecture de la variable -------------------------------


def test_missing_variable_renders_the_generic_header(make_app):
    body = make_app().test_client().get("/").get_data(as_text=True)
    assert header_label(body) == "HUB"


def test_configured_label_is_rendered(make_app):
    body = make_app("PORTAIL INTERNE").test_client().get("/").get_data(as_text=True)
    assert header_label(body) == "PORTAIL INTERNE"


def test_configuration_reads_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("HUB_BRAND_LABEL", "PORTAIL INTERNE")
    assert load_config(base_dir=tmp_path)["BRAND_LABEL"] == "PORTAIL INTERNE"
    monkeypatch.delenv("HUB_BRAND_LABEL")
    assert load_config(base_dir=tmp_path)["BRAND_LABEL"] == "HUB"


# --- Validation de l'entrée ----------------------------------------------------


def test_label_is_trimmed_and_normalized(monkeypatch, tmp_path):
    monkeypatch.setenv("HUB_BRAND_LABEL", "  Portail \t interne \n")
    assert load_config(base_dir=tmp_path)["BRAND_LABEL"] == "Portail interne"
    monkeypatch.setenv("HUB_BRAND_LABEL", "Portail\x07interne")
    assert load_config(base_dir=tmp_path)["BRAND_LABEL"] == "Portailinterne"


def test_blank_value_falls_back_to_the_generic_label(monkeypatch, tmp_path):
    for value in ("", "   ", "\t\n"):
        monkeypatch.setenv("HUB_BRAND_LABEL", value)
        assert load_config(base_dir=tmp_path)["BRAND_LABEL"] == "HUB"


def test_overlong_label_is_bounded(monkeypatch, tmp_path):
    monkeypatch.setenv("HUB_BRAND_LABEL", "A" * 200)
    label = load_config(base_dir=tmp_path)["BRAND_LABEL"]
    assert len(label) == BRAND_LABEL_MAX


def test_label_never_becomes_html(make_app):
    body = make_app('<script>alert(1)</script> & "citation"').test_client().get("/").get_data(as_text=True)
    assert header_label(body) == "&lt;script&gt;alert(1)&lt;/script&gt; &amp; &#34;citation&#34;"
    assert "<script>alert(1)" not in body


def test_label_is_escaped_in_the_admin_header(make_app):
    application = make_app("<b>MCO</b>")
    client = application.test_client()
    body = client.get("/admin/setup").get_data(as_text=True)
    assert header_label(body) == "&lt;b&gt;MCO&lt;/b&gt;"


# --- Purement visuel : aucun impact sur le reste -------------------------------


def test_branding_has_no_effect_beyond_the_rendering(make_app):
    default_app = make_app()
    labelled_app = make_app("PORTAIL INTERNE")
    assert labelled_app.config["TLS_HOSTNAME"] == default_app.config["TLS_HOSTNAME"]
    assert labelled_app.config["CERT_BACKEND"] == default_app.config["CERT_BACKEND"]
    assert labelled_app.config["DB_PATH"] == default_app.config["DB_PATH"]
    reference = default_app.test_client().get("/healthz").get_json()
    payload = labelled_app.test_client().get("/healthz").get_json()
    assert payload == reference
    assert "PORTAIL INTERNE" not in labelled_app.test_client().get("/healthz").get_data(as_text=True)


# --- Déploiement et documentation ----------------------------------------------


def test_deployment_files_expose_the_label_without_instance_value():
    for relative in VERSIONED_FILES:
        content = (REPO / relative).read_text(encoding="utf-8")
        if relative == ".env.example":
            assert "HUB_BRAND_LABEL" in content, relative
        else:
            assert "${HUB_BRAND_LABEL" in content, relative
    # Aucune valeur propre à une instance n'est figée dans le dépôt.
    for relative in VERSIONED_FILES:
        content = (REPO / relative).read_text(encoding="utf-8").lower()
        for value in ("mco-hub", "subnet-docker", "8448"):
            assert value not in content, f"valeur propre à une instance dans {relative} : {value}"


def test_label_is_documented():
    for relative in ("README.md", "docs/operations.md"):
        content = (REPO / relative).read_text(encoding="utf-8")
        assert "HUB_BRAND_LABEL" in content, relative
