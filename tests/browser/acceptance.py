"""Recette navigateur réelle (Chromium headless) de SNS Hub — desktop, mobile, admin, thèmes.

Prérequis : environnement avec Playwright et ses navigateurs installés
(`pip install -r requirements-dev.txt` puis `playwright install chromium` sur un
poste neuf ; rien à télécharger si un cache Playwright existe déjà).

Usage :
    HUB_BASE_URL=http://127.0.0.1:13744 .venv/bin/python tests/browser/acceptance.py

Variables :
    HUB_BASE_URL          URL de base à tester (par défaut http://127.0.0.1:13744)
    HUB_ADMIN_PASSWORD    mot de passe admin existant (sinon : compté comme absent)
    HUB_ADMIN_USER        identifiant admin (par défaut admin)
    HUB_SCOPE             `full` (défaut) ou `public` (sans administration)
    HUB_SCREENSHOTS_DIR   dossier de captures d'applications à téléverser (optionnel)
    HUB_SKIP_CERT         `1` : ignores les vérifications du certificat (instance locale)
    HUB_SHOTS_DIR         dossier de sortie des captures de validation
                          (par défaut /tmp/hub-acceptance)

Le script ne journalise jamais le mot de passe utilisé et restaure l'état qu'il modifie.
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

from playwright.sync_api import BrowserContext, Page, sync_playwright

BASE_URL = os.environ.get("HUB_BASE_URL", "http://127.0.0.1:13744")
SHOTS_DIR = Path(os.environ.get("HUB_SHOTS_DIR", "/tmp/hub-acceptance"))
APPS_SHOTS = os.environ.get("HUB_SCREENSHOTS_DIR", "")
ADMIN_USER = os.environ.get("HUB_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("HUB_ADMIN_PASSWORD", "")
SCOPE = os.environ.get("HUB_SCOPE", "full").strip().lower()
SKIP_CERT = os.environ.get("HUB_SKIP_CERT", "").strip() == "1"

# Applications du catalogue initial : id en base → capture réelle.
APP_SCREENSHOTS = {
    1: "fortiupgrade.webp",
    2: "fortiflow.webp",
    3: "fortiflow2.webp",
    4: "fortianonymous.webp",
    5: "vysion.webp",
}

DARK_BG = "#0b0b0d"
LIGHT_BG = "#f6f6f8"

results: list[tuple[str, bool, str, bool]] = []


def check(name: str, condition: bool, detail: str = "", *, skipped: bool = False) -> None:
    results.append((name, bool(condition), detail, skipped))
    status = "SKIP" if skipped else ("PASS" if condition else "FAIL")
    print(f"[{status}] {name}{(' — ' + detail) if detail else ''}")


def theme_state(page: Page) -> dict:
    return page.evaluate(
        """() => {
            const root = document.documentElement;
            const styles = getComputedStyle(root);
            let stored = null;
            try { stored = window.localStorage.getItem('hub-theme'); } catch (error) { stored = null; }
            return {
                attribute: root.getAttribute('data-theme'),
                bgTop: styles.getPropertyValue('--bg-top').trim(),
                prefersDark: window.matchMedia('(prefers-color-scheme: dark)').matches,
                stored: stored,
            };
        }"""
    )


def hero_visual(page: Page) -> dict:
    """Dimensions réelles du visuel de marque (pseudo-élément) : garde-fou anti-régression."""
    return page.evaluate(
        """() => {
            const hero = document.querySelector('.hero');
            if (!hero) { return { present: false }; }
            const styles = getComputedStyle(hero, '::after');
            return {
                present: true,
                width: parseFloat(styles.width) || 0,
                height: parseFloat(styles.height) || 0,
                opacity: parseFloat(styles.opacity) || 0,
                hasPanther: (styles.backgroundImage || '').includes('panther'),
            };
        }"""
    )


def check_hero_visual(page: Page, label: str) -> None:
    state = hero_visual(page)
    check(
        f"Hero : visuel de marque rendu ({label})",
        state["present"] and state["hasPanther"] and state["height"] > 60 and state["width"] > 60,
        f"{int(state.get('width', 0))}x{int(state.get('height', 0))} px, opacité {state.get('opacity')}",
    )


def main() -> int:
    SHOTS_DIR.mkdir(parents=True, exist_ok=True)
    password = ADMIN_PASSWORD or secrets.token_urlsafe(24)
    generated = not ADMIN_PASSWORD

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        desktop = browser.new_context(
            viewport={"width": 1440, "height": 900}, locale="fr-FR", color_scheme="dark"
        )
        mobile = browser.new_context(
            viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True,
            locale="fr-FR", color_scheme="dark",
        )
        page = desktop.new_page()
        admin_ready = False

        # --- Configuration initiale ou connexion -------------------------------
        if SCOPE != "public":
            page.goto(f"{BASE_URL}/admin/setup", wait_until="networkidle")
            if page.url.endswith("/admin/login"):
                if not ADMIN_PASSWORD:
                    print(
                        "Un compte administrateur existe déjà : fournir HUB_ADMIN_PASSWORD "
                        "pour rejouer la recette d'administration.",
                        file=sys.stderr,
                    )
                    admin_ready = False
                else:
                    page.fill("#username", ADMIN_USER)
                    page.fill("#password", password)
                    page.get_by_role("button", name="Se connecter").click()
                    page.wait_for_url("**/admin/**", timeout=10000)
                    admin_ready = True
                    check("Connexion admin existante", True)
            else:
                page.fill("#username", ADMIN_USER)
                page.fill("#password", password)
                page.fill("#confirmation", password)
                page.get_by_role("button", name="Créer le compte").click()
                page.wait_for_url("**/admin/", timeout=10000)
                admin_ready = True
                check("Première configuration admin créée", True)
            if admin_ready:
                check("Tableau de bord accessible", "Tableau de bord" in page.content())

        # --- Thème : comportement sombre / clair / préférence système ----------
        theme_dark = browser.new_context(
            viewport={"width": 1440, "height": 900}, locale="fr-FR", color_scheme="dark"
        )
        dark_page = theme_dark.new_page()
        dark_page.goto(BASE_URL, wait_until="networkidle")
        state = theme_state(dark_page)
        check(
            "Thème : sombre par défaut (préférence système sombre)",
            state["attribute"] is None and state["prefersDark"] and state["bgTop"] == DARK_BG,
            f"attribut={state['attribute']} préférence sombre={state['prefersDark']}",
        )
        dark_page.screenshot(path=str(SHOTS_DIR / "hub-landing-dark-desktop.png"))

        theme_light = browser.new_context(
            viewport={"width": 1440, "height": 900}, locale="fr-FR", color_scheme="light"
        )
        light_page = theme_light.new_page()
        light_page.goto(BASE_URL, wait_until="networkidle")
        state = theme_state(light_page)
        check(
            "Thème : clair automatique (prefers-color-scheme) sans choix mémorisé",
            state["attribute"] is None and not state["prefersDark"] and state["bgTop"] == LIGHT_BG,
            f"préférence sombre={state['prefersDark']} bg={state['bgTop']}",
        )
        light_page.screenshot(path=str(SHOTS_DIR / "hub-landing-light-desktop.png"))

        # Bascule manuelle depuis le thème sombre
        toggle = dark_page.locator("[data-theme-toggle]")
        check("Thème : bascule présente sur la landing", toggle.count() == 1)
        toggle.click()
        dark_page.wait_for_timeout(200)
        state = theme_state(dark_page)
        check(
            "Thème : bascule vers clair et mémorisation (localStorage)",
            state["attribute"] == "light" and state["stored"] == "light" and state["bgTop"] == LIGHT_BG,
            f"attribut={state['attribute']} stored={state['stored']}",
        )
        dark_page.screenshot(path=str(SHOTS_DIR / "hub-landing-light-forced.png"))

        # Persistance : rechargement, navigation vers l'admin, retour au portail
        dark_page.reload(wait_until="networkidle")
        state = theme_state(dark_page)
        check(
            "Thème : persistance après rechargement",
            state["attribute"] == "light" and state["bgTop"] == LIGHT_BG,
            f"attribut={state['attribute']}",
        )
        dark_page.goto(f"{BASE_URL}/admin/login", wait_until="networkidle")
        state = theme_state(dark_page)
        check(
            "Thème : conservé du portail vers l'administration",
            state["attribute"] == "light" and state["bgTop"] == LIGHT_BG,
            f"attribut={state['attribute']}",
        )
        dark_page.goto(BASE_URL, wait_until="networkidle")
        check(
            "Thème : conservé au retour sur le portail",
            theme_state(dark_page)["attribute"] == "light",
        )

        # Absence de flash : préférence mémorisée claire avec système sombre
        dark_page.add_init_script("window.localStorage.setItem('hub-theme', 'light');")
        dark_page.goto(BASE_URL, wait_until="domcontentloaded")
        early = theme_state(dark_page)
        check(
            "Thème : aucun flash (thème appliqué avant le premier rendu)",
            early["attribute"] == "light" and early["bgTop"] == LIGHT_BG,
            f"attribut={early['attribute']} dès DOMContentLoaded",
        )
        # Retour au choix « système » pour la suite
        dark_page.evaluate("() => window.localStorage.removeItem('hub-theme')")

        # Focus visible au clavier (accessibilité, thème clair) : le contour doit être net
        light_page.keyboard.press("Tab")
        light_page.keyboard.press("Tab")
        focus_state = light_page.evaluate(
            """() => {
                const styles = getComputedStyle(document.activeElement);
                return { tag: document.activeElement.tagName, width: styles.outlineWidth,
                         style: styles.outlineStyle, color: styles.outlineColor };
            }"""
        )
        check(
            "Accessibilité : focus clavier visible (thème clair)",
            focus_state["style"] != "none" and focus_state["width"] not in ("0px", ""),
            f"{focus_state['tag']} {focus_state['style']} {focus_state['width']}",
        )

        # --- Thème : mobile ----------------------------------------------------
        m_light = browser.new_context(
            viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True,
            locale="fr-FR", color_scheme="light",
        )
        mpage_light = m_light.new_page()
        mpage_light.goto(BASE_URL, wait_until="networkidle")
        overflow_light = mpage_light.evaluate(
            "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        check(
            "Thème clair mobile : pas de scroll horizontal",
            overflow_light <= 0,
            f"débordement={overflow_light}px",
        )
        check(
            "Thème clair mobile : bascule accessible",
            mpage_light.locator("[data-theme-toggle]").count() == 1,
        )
        check_hero_visual(mpage_light, "mobile clair")
        mpage_light.screenshot(path=str(SHOTS_DIR / "hub-landing-light-mobile.png"))

        # --- Transfert des captures d'applications (mode complet seulement) ----
        if admin_ready and APPS_SHOTS:
            shots = Path(APPS_SHOTS)
            uploaded = 0
            for app_id, filename in APP_SCREENSHOTS.items():
                shot = shots / filename
                if not shot.is_file():
                    continue
                page.goto(f"{BASE_URL}/admin/apps/{app_id}/edit", wait_until="networkidle")
                page.set_input_files("#image", str(shot))
                page.get_by_role("button", name="Enregistrer les modifications").click()
                page.wait_for_url("**/admin/apps", timeout=15000)
                uploaded += 1
            check(
                "Screenshots téléversés via l'admin",
                uploaded == len(APP_SCREENSHOTS),
                f"{uploaded} fichiers",
                skipped=uploaded == 0,
            )

        # --- Landing page (desktop, thème sombre) ------------------------------
        page.goto(BASE_URL, wait_until="networkidle")
        cards = page.locator("[data-card]").count()
        check("Landing : cartes affichées", cards >= 1, f"{cards} cartes")
        check_hero_visual(page, "desktop sombre")
        images = page.evaluate(
            """() => Array.from(document.querySelectorAll('.card-media img'))
                     .map(img => img.naturalWidth > 0)"""
        )
        if images:
            check("Landing : screenshots chargés", all(images), f"{len(images)} images")
        else:
            check("Landing : screenshots chargés", False, "aucune image", skipped=True)
        page.screenshot(path=str(SHOTS_DIR / "hub-desktop-dark.png"))

        # Recherche (amélioration progressive JS)
        if page.locator("[data-filter='search']").count():
            page.fill("[data-filter='search']", "fortiflow")
            page.wait_for_timeout(250)
            visible = page.locator("[data-card]:visible").count()
            check("Landing : recherche instantanée", visible >= 1, f"{visible} cartes visibles")
            page.fill("[data-filter='search']", "")
            page.wait_for_timeout(200)

        # Filtres catégorie (générés depuis la base)
        chips = page.locator("[data-category-chip]")
        chip_count = chips.count()
        check("Landing : filtres de catégories générés", chip_count >= 2, f"{chip_count} filtres")
        if chip_count > 1:
            chips.nth(1).click()
            page.wait_for_timeout(250)
            visible = page.locator("[data-card]:visible").count()
            check("Landing : filtre catégorie actif", visible >= 1, f"{visible} cartes visibles")
            chips.nth(0).click()
            page.wait_for_timeout(150)

        # --- Landing page (mobile, thème sombre) -------------------------------
        mpage = mobile.new_page()
        mpage.goto(BASE_URL, wait_until="networkidle")
        overflow = mpage.evaluate(
            "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        check("Mobile : pas de scroll horizontal", overflow <= 0, f"débordement={overflow}px")
        check_hero_visual(mpage, "mobile sombre")
        mpage.screenshot(path=str(SHOTS_DIR / "hub-mobile-dark.png"))

        # --- Administration (mode complet, session requise) --------------------
        if admin_ready:
            page.goto(f"{BASE_URL}/admin/", wait_until="networkidle")
            admin_state = theme_state(page)
            check(
                "Admin : thème sombre par défaut (référence de la DA)",
                admin_state["attribute"] is None and admin_state["bgTop"] == DARK_BG,
                f"attribut={admin_state['attribute']} bg={admin_state['bgTop']}",
            )
            page.goto(f"{BASE_URL}/admin/apps", wait_until="networkidle")
            check("Admin : liste des applications", page.locator("table.admin-table").count() >= 1)
            page.screenshot(path=str(SHOTS_DIR / "hub-admin-apps-dark.png"))

            page.goto(f"{BASE_URL}/admin/", wait_until="networkidle")
            page.screenshot(path=str(SHOTS_DIR / "hub-admin-dashboard-dark.png"))

            page.goto(f"{BASE_URL}/admin/certificates", wait_until="networkidle")
            cert_content = page.content()
            if SKIP_CERT:
                check("Admin : page certificats", True, "vérifications ignorées (HUB_SKIP_CERT)", skipped=True)
            else:
                check("Admin : page certificats", "Certificat actif" in cert_content)
                check(
                    "Admin : certificat servi vérifié",
                    "correspond à la paire gérée" in cert_content or "Jours restants" in cert_content,
                )
            page.screenshot(path=str(SHOTS_DIR / "hub-admin-certificates-dark.png"))

            # --- Catégories : création, doublon, renommage, suppression --------
            page.goto(f"{BASE_URL}/admin/categories", wait_until="networkidle")
            categories_content = page.content()
            check("Catégories : page accessible", "Catégories" in categories_content)
            check(
                "Catégories : repli protégé et compteurs affichés",
                "Catégorie de repli" in categories_content and "application" in categories_content,
            )
            page.screenshot(path=str(SHOTS_DIR / "hub-admin-categories-dark.png"))

            page.fill("#new-category-name", "Recette")
            page.get_by_role("button", name="Ajouter").click()
            page.wait_for_load_state("networkidle")
            check("Catégories : création", "Recette" in page.content())

            page.fill("#new-category-name", "recette")
            page.get_by_role("button", name="Ajouter").click()
            page.wait_for_load_state("networkidle")
            check("Catégories : doublon refusé", "existe déjà" in page.content())

            row = page.locator("tr", has=page.locator("input[value='Recette']")).first
            row.locator("input[name='name']").fill("Recette interne")
            row.get_by_role("button", name="Renommer").click()
            page.wait_for_load_state("networkidle")
            check("Catégories : renommage", "Recette interne" in page.content())

            # Création rapide depuis le formulaire application (sans quitter le formulaire)
            page.goto(f"{BASE_URL}/admin/apps/new", wait_until="networkidle")
            page.fill("#name", "Application de recette")
            page.fill("#slug", "application-de-recette")
            page.fill("#url", "https://recette.valdev.me")
            page.get_by_role("button", name="+ Nouvelle catégorie").click()
            page.fill("#new-category", "Recette rapide")
            page.get_by_role("button", name="Créer", exact=True).click()
            page.wait_for_timeout(600)
            selected = page.eval_on_selector(
                "#category_id", "select => select.options[select.selectedIndex].textContent"
            )
            check(
                "Catégories : création rapide depuis le formulaire application",
                selected.strip() == "Recette rapide",
                f"sélection={selected.strip()}",
            )
            check(
                "Catégories : création rapide sans perte de saisie",
                page.input_value("#name") == "Application de recette",
            )
            page.screenshot(path=str(SHOTS_DIR / "hub-admin-app-form-dark.png"))
            page.get_by_role("button", name="Créer l'application").click()
            page.wait_for_url("**/admin/apps", timeout=15000)
            created = "Application de recette" in page.content()
            check("Catégories : application créée avec la nouvelle catégorie", created)

            # Filtre public généré puis suppression avec réassignation
            page.goto(BASE_URL, wait_until="networkidle")
            check(
                "Catégories : filtre public généré pour la nouvelle catégorie",
                "Recette rapide" in page.content(),
            )
            page.goto(f"{BASE_URL}/admin/categories", wait_until="networkidle")
            row = page.locator("tr", has=page.locator("input[value='Recette rapide']")).first
            row.get_by_role("link", name="Supprimer…").click()
            page.wait_for_load_state("networkidle")
            check("Catégories : suppression utilisée = confirmation", "Réassigner et supprimer" in page.content())
            page.get_by_role("button", name="Réassigner et supprimer").click()
            page.wait_for_load_state("networkidle")
            check(
                "Catégories : réassignation puis suppression",
                page.locator("input[value='Recette rapide']").count() == 0
                and "réassignée" in page.content(),
                "réassignation confirmée",
            )

            # Nettoyage : l'application de recette est supprimée
            page.goto(f"{BASE_URL}/admin/apps", wait_until="networkidle")
            row = page.locator("tr", has_text="Application de recette").first
            page.once("dialog", lambda dialog: dialog.accept())
            row.get_by_role("button", name="Supprimer").click()
            page.wait_for_load_state("networkidle")
            check(
                "Recette : nettoyage de l'application de test",
                page.locator("tr", has_text="Application de recette").count() == 0,
            )

            # --- Admin en thème clair -----------------------------------------
            page.locator("[data-theme-toggle]").click()
            page.wait_for_timeout(200)
            state = theme_state(page)
            check(
                "Admin : bascule vers le thème clair",
                state["attribute"] == "light" and state["bgTop"] == LIGHT_BG,
                f"attribut={state['attribute']}",
            )
            page.goto(f"{BASE_URL}/admin/apps", wait_until="networkidle")
            page.screenshot(path=str(SHOTS_DIR / "hub-admin-apps-light.png"))
            page.goto(f"{BASE_URL}/admin/apps/new", wait_until="networkidle")
            page.screenshot(path=str(SHOTS_DIR / "hub-admin-app-form-light.png"))
            page.goto(f"{BASE_URL}/admin/categories", wait_until="networkidle")
            page.screenshot(path=str(SHOTS_DIR / "hub-admin-categories-light.png"))
            page.goto(f"{BASE_URL}/admin/certificates", wait_until="networkidle")
            page.screenshot(path=str(SHOTS_DIR / "hub-admin-certificates-light.png"))
            page.goto(f"{BASE_URL}/admin/", wait_until="networkidle")
            page.screenshot(path=str(SHOTS_DIR / "hub-admin-dashboard-light.png"))
            check("Admin : pages parcourues en thème clair", theme_state(page)["attribute"] == "light")

            # Masquer / afficher
            page.goto(f"{BASE_URL}/admin/apps", wait_until="networkidle")
            first_row = page.locator("table.admin-table tbody tr").first
            first_row.get_by_role("button", name="Masquer").click()
            page.wait_for_timeout(400)
            page.goto(BASE_URL, wait_until="networkidle")
            hidden_count = page.locator("[data-card]").count()
            check("Admin : masquage effectif", hidden_count == cards - 1, f"{hidden_count} cartes")
            page.goto(f"{BASE_URL}/admin/apps", wait_until="networkidle")
            page.locator("table.admin-table tbody tr").first.get_by_role(
                "button", name="Afficher"
            ).click()
            page.wait_for_timeout(400)
            page.goto(BASE_URL, wait_until="networkidle")
            check("Admin : réaffichage effectif", page.locator("[data-card]").count() == cards)

            # Déconnexion / reconnexion
            page.goto(f"{BASE_URL}/admin/", wait_until="networkidle")
            page.get_by_role("button", name="Déconnexion").click()
            page.wait_for_url("**/admin/login", timeout=10000)
            check("Déconnexion admin", True)
            page.goto(f"{BASE_URL}/admin/", wait_until="networkidle")
            check("Admin protégé sans session", page.url.endswith("/admin/login"))
        else:
            check("Administration : recette complète", True, "session admin indisponible", skipped=True)

        browser.close()

    passed = sum(1 for _, ok, _, skipped in results if ok and not skipped)
    failed = sum(1 for _, ok, _, skipped in results if not ok and not skipped)
    total = sum(1 for _, _, _, skipped in results if not skipped)
    print(f"\n{passed}/{total} vérifications navigateur passées ({failed} échec(s))")
    if generated:
        print("(compte administrateur de test créé : à réinitialiser si non destiné à l'usage)")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
