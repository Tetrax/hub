"""Thème clair/sombre : intégration, absence de flash, compatibilité CSP."""

from __future__ import annotations

import re

from conftest import create_catalog_app, session_csrf

THEME_ATTRIBUTE = 'data-theme="light"'
THEME_INIT = "/static/js/theme-init.js"


def test_theme_init_runs_before_stylesheet(client):
    body = client.get("/").get_data(as_text=True)
    assert THEME_INIT in body
    assert body.index(THEME_INIT) < body.index("/static/css/hub.css")
    # Le thème doit aussi être annoncé avant le CSS pour éviter tout fond parasite.
    assert body.index('name="color-scheme"') < body.index("/static/css/hub.css")


def test_no_inline_script_so_csp_stays_strict(client):
    body = client.get("/").get_data(as_text=True)
    scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", body, flags=re.DOTALL)
    assert scripts, "aucune balise script attendue ?"
    for attributes, content in scripts:
        assert "src=" in attributes, "script inline interdit par la CSP"
        assert content.strip() == ""


def test_theme_toggle_present_on_public_and_admin(app, client, admin):
    public = client.get("/").get_data(as_text=True)
    assert "data-theme-toggle" in public
    assert 'type="button"' in public.split("data-theme-toggle")[0][-120:]
    for path in (
        "/admin/login",
        "/admin/",
        "/admin/apps",
        "/admin/apps/new",
        "/admin/categories",
        "/admin/settings",
    ):
        page = admin.get(path).get_data(as_text=True)
        assert "data-theme-toggle" in page, f"toggle absent sur {path}"
        assert "theme-icon-sun" in page and "theme-icon-moon" in page


def test_theme_toggle_on_setup_page(app, client):
    page = client.get("/admin/setup").get_data(as_text=True)
    assert "data-theme-toggle" in page


def test_theme_init_asset_is_served(client):
    response = client.get(THEME_INIT)
    assert response.status_code == 200
    script = response.get_data(as_text=True)
    assert "hub-theme" in script
    assert "localStorage" in script
    assert "data-theme" in script
    # Aucun thème n'est forcé : sans choix mémorisé, la préférence système s'applique.
    assert "prefers-color-scheme" not in script


def test_hub_js_handles_toggle_and_quick_add(client):
    script = client.get("/static/js/hub.js").get_data(as_text=True)
    assert "data-theme-toggle" in script
    assert "hub-theme" in script
    assert "prefers-color-scheme: light" in script
    assert "data-quick-add" in script
    assert "category_quick_create" not in script  # point d'entrée fourni par le gabarit


def test_stylesheet_defines_both_themes(client):
    css = client.get("/static/css/hub.css").get_data(as_text=True)
    assert THEME_ATTRIBUTE in css
    assert "@media (prefers-color-scheme: light)" in css
    assert ":root:not([data-theme=\"dark\"])" in css
    assert "--rose: #f4a8c9" in css  # accent SNS conservé dans les deux thèmes
    assert "color-scheme: light dark" in css
    assert ":root[data-theme=\"light\"] { color-scheme: light; }" in css
    for token in ("--bg-top", "--panel", "--text", "--border", "--muted", "--media-ring"):
        assert f"{token}:" in css
    assert "prefers-reduced-motion" in css


def test_light_theme_values_are_declared_twice_identically(client):
    """Les deux blocs clairs (système et choix explicite) doivent rester identiques."""
    css = client.get("/static/css/hub.css").get_data(as_text=True)
    media_block = css.split("@media (prefers-color-scheme: light)")[1].split("}\n}")[0]
    attribute_block = css.split(':root[data-theme="light"] {')[1].split("\n}")[0]
    assert media_block.count("--") > 20
    assert attribute_block.count("--") > 20
    for token in ("--bg-top", "--text", "--border", "--rose-pale", "--media-ring"):
        media_value = re.search(rf"{token}: ([^;]+);", media_block)
        attribute_value = re.search(rf"{token}: ([^;]+);", attribute_block)
        assert media_value is not None and attribute_value is not None, token
        assert media_value.group(1) == attribute_value.group(1), token


def test_hero_and_branding_adapt_to_theme(client):
    css = client.get("/static/css/hub.css").get_data(as_text=True)
    assert "--hero-opacity" in css and "--hero-mask" in css
    assert "--logo-filter" in css


def test_quick_add_is_progressive_enhancement(app, admin):
    page = admin.get("/admin/apps/new").get_data(as_text=True)
    assert "data-quick-add hidden" in page
    assert "data-quick-add-toggle hidden" in page
    assert 'data-endpoint="/admin/categories/quick-create"' in page
    # L'input de création rapide ne doit pas être soumis avec le formulaire application.
    assert 'id="new-category"' in page
    assert 'name="new-category"' not in page


def test_filters_remain_links_without_js(app, client, admin):
    create_catalog_app(app, slug="flow", name="FortiFlow", category="Fortinet")
    page = client.get("/").get_data(as_text=True)
    assert 'href="/?category=fortinet"' in page
    assert 'class="chip' in page


def test_version_is_displayed(client):
    body = client.get("/").get_data(as_text=True)
    assert "SNS Hub v1.1.0" in body
