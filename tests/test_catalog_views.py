"""Vue catalogue : Cartes (par défaut) et Liste — un seul jeu de données, deux rendus."""

from __future__ import annotations

import re
import sqlite3

from conftest import create_catalog_app

VIEW_KEY = "hub_catalog_view"
VIEW_INIT = "/static/js/catalog-view-init.js"


def split_panels(body: str) -> tuple[str, str]:
    """(HTML de la vue cartes, HTML de la vue liste) — la page rend les deux."""
    cards = body.split('data-view-panel="cards"', 1)[1].split('data-view-panel="list"', 1)[0]
    listing = body.split('data-view-panel="list"', 1)[1]
    return cards, listing


def item_datasets(html: str) -> list[tuple[str, str, str]]:
    """Triplets (nom, description, catégorie) des éléments de catalogue d'un rendu."""
    datasets = []
    for chunk in re.split(r"\bdata-app\b", html)[1:]:
        name = re.search(r'data-name="([^"]*)"', chunk)
        description = re.search(r'data-description="([^"]*)"', chunk)
        category = re.search(r'data-category="([^"]*)"', chunk)
        assert name and description and category, "élément de catalogue incomplet"
        datasets.append((name.group(1), description.group(1), category.group(1)))
    return datasets


def render_landing(app, client, query: str = "") -> tuple[str, str]:
    body = client.get("/" + query).get_data(as_text=True)
    return split_panels(body)


# --- Deux rendus, un seul catalogue --------------------------------------------


def test_both_views_render_the_same_catalogue(app, client):
    create_catalog_app(app, slug="flow", name="FortiFlow", category="Fortinet")
    create_catalog_app(app, slug="vysion", name="Vysion", category="Sécurité", status="beta")
    hidden_id = create_catalog_app(app, slug="cachee", name="Cachee")
    connection = sqlite3.connect(app.config["DB_PATH"])
    connection.execute("UPDATE apps SET enabled = 0 WHERE id = ?", (hidden_id,))
    connection.commit()
    connection.close()

    cards, listing = render_landing(app, client)
    assert [name for name, _, _ in item_datasets(cards)] == ["fortiflow", "vysion"]
    assert item_datasets(listing) == item_datasets(cards)
    assert "Cachee" not in cards and "Cachee" not in listing


def test_list_shows_name_category_status_description_and_cta(app, client):
    create_catalog_app(
        app, slug="flow", name="FortiFlow", category="Fortinet", status="production",
        description="Analyse de logs FortiGate.",
    )
    cards, listing = render_landing(app, client)
    assert "FortiFlow" in listing
    assert 'class="row-category">Fortinet' in listing
    assert 'badge badge-production' in listing
    assert "Analyse de logs FortiGate." in listing
    assert "Ouvrir l'application" in listing
    # Le CTA de la liste pointe vers la même URL que la carte, même comportement d'ouverture.
    assert re.findall(r'class="row-link" href="([^"]+)"', listing) == re.findall(
        r'class="card-link" href="([^"]+)"', cards
    )
    assert listing.count('target="_blank"') == cards.count('target="_blank"') == 1


def test_list_never_renders_screenshots(app, client):
    create_catalog_app(app, slug="flow", name="FortiFlow")
    image = "0123456789abcdef0123456789abcdef.webp"
    connection = sqlite3.connect(app.config["DB_PATH"])
    connection.execute("UPDATE apps SET image = ?", (image,))
    connection.commit()
    connection.close()

    cards, listing = render_landing(app, client)
    assert image in cards and "<img" in cards
    assert "<img" not in listing
    assert image not in listing
    assert "card-media" not in listing


def test_list_status_reuses_existing_badges(app, client):
    create_catalog_app(app, slug="flow", name="FortiFlow", status="beta")
    _, listing = render_landing(app, client)
    assert 'badge badge-beta' in listing
    assert "Bêta" in listing


# --- Bascule de vue ------------------------------------------------------------


def test_default_rendering_is_the_cards_view(app, client):
    create_catalog_app(app, slug="flow", name="FortiFlow")
    body = client.get("/").get_data(as_text=True)
    # Aucun attribut serveur : sans JavaScript ni choix mémorisé, la vue Cartes s'applique.
    assert "data-catalog-view" not in body
    assert "data-card" in body
    assert "Aucun outil ne correspond" in body  # état vide partagé, rendu une fois


def test_view_switch_is_progressive_enhancement(app, client):
    create_catalog_app(app, slug="flow", name="FortiFlow")
    body = client.get("/").get_data(as_text=True)
    assert re.search(r'data-view-switch[^>]*hidden', body, flags=re.DOTALL), (
        "la bascule doit rester masquée sans JavaScript"
    )
    assert re.search(
        r'data-view-button="cards"[^>]*aria-pressed="true"', body
    ), "état actif initial = Cartes"
    assert re.search(r'data-view-button="list"[^>]*aria-pressed="false"', body)
    assert body.count("data-result-count") == 1
    assert body.count("data-empty-state") == 1


def test_hub_js_drives_the_view_switch_and_the_shared_counter(client):
    script = client.get("/static/js/hub.js").get_data(as_text=True)
    assert VIEW_KEY in script
    assert "data-view-switch" in script
    assert "data-view-button" in script
    assert 'aria-pressed' in script
    assert "[data-app]" in script  # moteur de filtre unique, les deux rendus
    assert 'data-view-panel="' in script  # décompte selon la vue affichée
    assert "data-result-count" in script
    assert "view-animate" in script


def test_view_init_script_applies_the_memorized_view_before_render(client):
    body = client.get("/").get_data(as_text=True)
    assert VIEW_INIT in body
    assert body.index(VIEW_INIT) < body.index("/static/css/hub.css")
    script = client.get(VIEW_INIT).get_data(as_text=True)
    assert VIEW_KEY in script
    assert "data-catalog-view" in script
    # Seule la vue Liste est forcée : sans choix, le comportement par défaut (cartes) reste.
    assert '"list"' in script
    assert "localStorage" in script


# --- Filtres partagés (recherche, catégories) ----------------------------------


def test_server_side_filters_apply_to_both_views(app, client):
    create_catalog_app(app, slug="flow", name="FortiFlow", category="Fortinet")
    create_catalog_app(app, slug="anon", name="FortiAnonymous", category="Sécurité")

    cards, listing = render_landing(app, client, "?category=fortinet")
    assert [name for name, _, _ in item_datasets(cards)] == ["fortiflow"]
    assert item_datasets(listing) == item_datasets(cards)

    cards, listing = render_landing(app, client, "?q=anon")
    assert [name for name, _, _ in item_datasets(listing)] == ["fortianonymous"]
    assert item_datasets(cards) == item_datasets(listing)


def test_category_chips_remain_links_without_js(app, client):
    create_catalog_app(app, slug="flow", name="FortiFlow", category="Fortinet")
    body = client.get("/").get_data(as_text=True)
    assert 'href="/?category=fortinet"' in body
    assert 'data-category="fortinet"' in body  # les deux rendus portent la catégorie


# --- Styles et accessibilité ---------------------------------------------------


def test_stylesheet_switches_views_from_the_html_attribute(client):
    css = client.get("/static/css/hub.css").get_data(as_text=True)
    assert '[data-view-panel="list"] { display: none; }' in css
    assert ':root[data-catalog-view="list"] [data-view-panel="list"] { display: block; }' in css
    assert ':root[data-catalog-view="list"] [data-view-panel="cards"] { display: none; }' in css
    assert ".row-link" in css and ".rows" in css and ".row-desc" in css
    assert '.view-btn[aria-pressed="true"]' in css
    assert "@keyframes view-fade-in" in css
    # Les deux thèmes restent des tokens : aucun composant de la vue liste ne code une couleur.
    row_start = css.index(".row {")
    row_block = css[row_start : css.index("}", row_start)]
    assert "#" not in row_block, "couleur codée en dur dans la vue liste"


def test_badge_position_is_contextual_not_duplicated(client):
    css = client.get("/static/css/hub.css").get_data(as_text=True)
    base = css[css.index(".badge {") : css.index("}", css.index(".badge {"))]
    assert "position" not in base
    assert ".card-media .badge { position: absolute" in css
    assert ".badge-production" in css and ".badge-beta" in css  # couleurs uniques réutilisées


def test_reduced_motion_is_respected_for_the_view_transition(client):
    css = client.get("/static/css/hub.css").get_data(as_text=True)
    assert "prefers-reduced-motion" in css
    assert "animation: none !important" in css
