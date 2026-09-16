"""Validations d'entrées et stockage des images (modules purs)."""

from __future__ import annotations

import pytest

from app import uploads
from app.urls import (
    STATUS_LABELS,
    slugify,
    validate_app_url,
    validate_description,
    validate_name,
    validate_slug,
    validate_status,
)


# --- URLs ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://fortiflow.valdev.me",
        "http://10.0.0.5:8080/app",
        "https://example.com/path?x=1#frag",
    ],
)
def test_valid_urls(url):
    normalized, error = validate_app_url(url)
    assert error is None and normalized == url


@pytest.mark.parametrize(
    "url,expected",
    [
        ("javascript:alert(1)", "schémas"),
        ("data:text/html;base64,AAA", "schémas"),
        ("file:///etc/passwd", "schémas"),
        ("ftp://example.com", "schémas"),
        ("exemple.com", "schémas"),
        ("", "obligatoire"),
        ("https://", "nom d'hôte"),
        ("https://user:pass@example.com", "identifiants"),
        ("https://exemple .com", "espace"),
        ("https://example.com:99999", "Port invalide"),
        ("https://example.com\nX", "espace"),
    ],
)
def test_rejected_urls(url, expected):
    normalized, error = validate_app_url(url)
    assert normalized is None
    assert expected in error


def test_url_length_limit():
    long_url = "https://example.com/" + "a" * 2100
    _, error = validate_app_url(long_url)
    assert error is not None and "trop longue" in error


# --- Slugs / noms / statuts ----------------------------------------------------


def test_slugify():
    assert slugify("FortiFlow") == "fortiflow"
    assert slugify("Éditeur Réseau  Interne") == "editeur-reseau-interne"
    assert slugify("---") == "app"
    assert len(slugify("x" * 200)) <= 48


@pytest.mark.parametrize("slug", ["ok-slug", "a1", "forti-flow-2"])
def test_valid_slugs(slug):
    assert validate_slug(slug)[1] is None


def test_slug_is_normalized_lowercase():
    slug, error = validate_slug("  Majuscule-OK  ")
    assert error is None and slug == "majuscule-ok"


@pytest.mark.parametrize("slug", ["-mauvais", "mauvais-", "avec espace", "a", "trop" * 30])
def test_invalid_slugs(slug):
    assert validate_slug(slug)[1] is not None


def test_name_and_description_limits():
    assert validate_name("")[1] is not None
    assert validate_name("x" * 81)[1] is not None
    assert validate_name("FortiFlow")[1] is None
    assert validate_description("x" * 401)[1] is not None
    assert validate_description("Description courte.")[1] is None


def test_category_name_validation():
    from app.urls import validate_category_name

    assert validate_category_name("  Réseau  ")[0] == "Réseau"
    assert validate_category_name("Interne   SNS")[0] == "Interne SNS"
    assert validate_category_name("")[1] is not None
    assert validate_category_name("x" * 41)[1] is not None
    assert validate_category_name("bad\x00name")[1] is not None
    assert validate_status("Production")[0] == "production"
    assert validate_status("inconnu")[1] is not None


# --- Uploads -------------------------------------------------------------------


def test_detect_image_type(monkeypatch):
    from conftest import JPEG_LIKE, PNG_BYTES, WEBP_LIKE

    assert uploads.detect_image_type(PNG_BYTES) == "png"
    assert uploads.detect_image_type(JPEG_LIKE) == "jpg"
    assert uploads.detect_image_type(WEBP_LIKE) == "webp"
    assert uploads.detect_image_type(b"GIF89a" + b"\x00" * 10) is None
    assert uploads.detect_image_type(b"") is None
    assert uploads.detect_image_type(b"\x89PNG") is None


def test_save_and_delete_screenshot(tmp_path):
    from conftest import PNG_BYTES

    class Storage:
        filename = "capture.png"

        def read(self, size=-1):
            return PNG_BYTES

    name, error = uploads.save_screenshot(Storage(), tmp_path, 1024 * 1024)
    assert error is None and uploads.is_valid_image_name(name)
    assert (tmp_path / name).read_bytes() == PNG_BYTES
    uploads.delete_screenshot(tmp_path, name)
    assert not (tmp_path / name).exists()


def test_save_rejects_bad_content(tmp_path):
    class Storage:
        filename = "capture.png"

        def read(self, size=-1):
            return b"contenu arbitraire"

    name, error = uploads.save_screenshot(Storage(), tmp_path, 1024)
    assert name is None and "Format non pris en charge" in error


def test_save_rejects_oversize(tmp_path):
    from conftest import PNG_BYTES

    class Storage:
        filename = "capture.png"

        def read(self, size=-1):
            return PNG_BYTES + b"\x00" * 5000

    name, error = uploads.save_screenshot(Storage(), tmp_path, 1024)
    assert name is None and "trop volumineux" in error


def test_delete_only_managed_names(tmp_path):
    victim = tmp_path / "important.txt"
    victim.write_text("à conserver")
    uploads.delete_screenshot(tmp_path, "../important.txt")
    uploads.delete_screenshot(tmp_path, "important.txt")
    uploads.delete_screenshot(tmp_path, None)
    assert victim.exists()


def test_orphan_detection(tmp_path):
    from conftest import PNG_BYTES

    referenced = "a" * 32 + ".png"
    orphan = "b" * 32 + ".png"
    (tmp_path / referenced).write_bytes(PNG_BYTES)
    (tmp_path / orphan).write_bytes(PNG_BYTES)
    (tmp_path / "ignore.txt").write_text("x")
    assert uploads.orphan_files(tmp_path, {referenced}) == [orphan]
