"""Recette navigateur réelle (Chromium headless) de SNS Hub — desktop, mobile, admin.

Prérequis : environnement avec Playwright et ses navigateurs installés
(`pip install -r requirements-dev.txt` puis `playwright install chromium` sur un
poste neuf ; rien à télécharger si un cache Playwright existe déjà).

Usage :
    HUB_BASE_URL=http://127.0.0.1:13744 .venv/bin/python tests/browser/acceptance.py

Variables :
    HUB_BASE_URL          URL de base à tester (par défaut http://127.0.0.1:13744)
    HUB_ADMIN_PASSWORD    mot de passe admin existant (sinon : compté comme absent)
    HUB_SCREENSHOTS_DIR   dossier de captures d'applications à téléverser (optionnel)
    HUB_SHOTS_DIR         dossier de sortie des captures de validation
                          (par défaut /tmp/hub-acceptance)

Le script ne journalise jamais le mot de passe utilisé.
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE_URL = os.environ.get("HUB_BASE_URL", "http://127.0.0.1:13744")
SHOTS_DIR = Path(os.environ.get("HUB_SHOTS_DIR", "/tmp/hub-acceptance"))
APPS_SHOTS = os.environ.get("HUB_SCREENSHOTS_DIR", "")
ADMIN_USER = os.environ.get("HUB_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("HUB_ADMIN_PASSWORD", "")

# Applications du catalogue initial : id en base → capture réelle.
APP_SCREENSHOTS = {
    1: "fortiupgrade.png",
    2: "fortiflow.png",
    3: "fortiflow2.png",
    4: "fortianonymous.png",
    5: "vysion.png",
}

results: list[tuple[str, bool, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    results.append((name, bool(condition), detail))
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}{(' — ' + detail) if detail else ''}")


def main() -> int:
    SHOTS_DIR.mkdir(parents=True, exist_ok=True)
    password = ADMIN_PASSWORD or secrets.token_urlsafe(24)
    generated = not ADMIN_PASSWORD

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        desktop = browser.new_context(viewport={"width": 1440, "height": 900}, locale="fr-FR")
        mobile = browser.new_context(
            viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True, locale="fr-FR"
        )
        page = desktop.new_page()

        # --- Configuration initiale ou connexion -------------------------------
        page.goto(f"{BASE_URL}/admin/setup", wait_until="networkidle")
        if page.url.endswith("/admin/login"):
            if not ADMIN_PASSWORD:
                print(
                    "Un compte administrateur existe déjà : fournir HUB_ADMIN_PASSWORD "
                    "pour rejouer la recette.",
                    file=sys.stderr,
                )
                return 2
            page.fill("#username", ADMIN_USER)
            page.fill("#password", password)
            page.get_by_role("button", name="Se connecter").click()
            page.wait_for_url("**/admin/**", timeout=10000)
            check("Connexion admin existante", True)
        else:
            page.fill("#username", ADMIN_USER)
            page.fill("#password", password)
            page.fill("#confirmation", password)
            page.get_by_role("button", name="Créer le compte").click()
            page.wait_for_url("**/admin/", timeout=10000)
            check("Première configuration admin créée", True)
        check("Tableau de bord accessible", "Tableau de bord" in page.content())

        # --- Téléversement des captures d'applications -------------------------
        if APPS_SHOTS:
            shots = Path(APPS_SHOTS)
            uploaded = 0
            for app_id, filename in APP_SCREENSHOTS.items():
                shot = shots / filename
                if not shot.is_file():
                    continue
                page.goto(f"{BASE_URL}/admin/apps/{app_id}/edit", wait_until="networkidle")
                page.set_input_files("#image", str(shot))
                # Cibler le bouton du formulaire principal (le bouton de déconnexion
                # de la barre latérale précède dans le DOM).
                page.get_by_role("button", name="Enregistrer les modifications").click()
                page.wait_for_url("**/admin/apps", timeout=15000)
                uploaded += 1
            check("Screenshots téléversés via l'admin", uploaded == len(APP_SCREENSHOTS), f"{uploaded} fichiers")

        # --- Landing page (desktop) --------------------------------------------
        page.goto(BASE_URL, wait_until="networkidle")
        cards = page.locator("[data-card]").count()
        check("Landing : cartes affichées", cards >= 1, f"{cards} cartes")
        images = page.evaluate(
            """() => Array.from(document.querySelectorAll('.card-media img'))
                     .map(img => img.naturalWidth > 0)"""
        )
        check("Landing : screenshots chargés", bool(images) and all(images), f"{len(images)} images")
        page.screenshot(path=str(SHOTS_DIR / "hub-desktop.png"), full_page=False)

        # Recherche (amélioration progressive JS)
        if page.locator("[data-filter='search']").count():
            page.fill("[data-filter='search']", "fortiflow")
            page.wait_for_timeout(250)
            visible = page.locator("[data-card]:visible").count()
            check("Landing : recherche instantanée", visible == 2, f"{visible} cartes visibles")
            page.fill("[data-filter='search']", "")
            page.wait_for_timeout(200)

        # Filtre catégorie
        chips = page.locator("[data-category-chip]")
        if chips.count() > 1:
            chips.nth(1).click()
            page.wait_for_timeout(250)
            visible = page.locator("[data-card]:visible").count()
            check("Landing : filtre catégorie", visible >= 1, f"{visible} cartes visibles")
            chips.nth(0).click()
            page.wait_for_timeout(150)

        # --- Landing page (mobile) ---------------------------------------------
        mpage = mobile.new_page()
        mpage.goto(BASE_URL, wait_until="networkidle")
        overflow = mpage.evaluate(
            "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        check("Mobile : pas de scroll horizontal", overflow <= 0, f"débordement={overflow}px")
        mpage.screenshot(path=str(SHOTS_DIR / "hub-mobile.png"), full_page=False)

        # --- Administration -----------------------------------------------------
        page.goto(f"{BASE_URL}/admin/apps", wait_until="networkidle")
        check("Admin : liste des applications", page.locator("table.admin-table").count() == 1)
        page.screenshot(path=str(SHOTS_DIR / "hub-admin-apps.png"))

        page.goto(f"{BASE_URL}/admin/", wait_until="networkidle")
        page.screenshot(path=str(SHOTS_DIR / "hub-admin-dashboard.png"))

        page.goto(f"{BASE_URL}/admin/certificates", wait_until="networkidle")
        cert_content = page.content()
        check("Admin : page certificats", "Certificat actif" in cert_content)
        check(
            "Admin : certificat servi vérifié",
            "correspond à la paire gérée" in cert_content or "Jours restants" in cert_content,
        )
        page.screenshot(path=str(SHOTS_DIR / "hub-admin-certificates.png"))

        # Masquer / afficher
        page.goto(f"{BASE_URL}/admin/apps", wait_until="networkidle")
        first_row = page.locator("table.admin-table tbody tr").first
        first_row.get_by_role("button", name="Masquer").click()
        page.wait_for_timeout(400)
        page.goto(BASE_URL, wait_until="networkidle")
        hidden_count = page.locator("[data-card]").count()
        check("Admin : masquage effectif", hidden_count == cards - 1, f"{hidden_count} cartes")
        page.goto(f"{BASE_URL}/admin/apps", wait_until="networkidle")
        page.locator("table.admin-table tbody tr").first.get_by_role("button", name="Afficher").click()
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

        browser.close()

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n{passed}/{len(results)} vérifications navigateur passées")
    if generated:
        print("(compte administrateur de test créé : à réinitialiser si non destiné à l'usage)")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
