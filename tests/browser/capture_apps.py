"""Captures réelles des applications SNS pour le catalogue Hub (poste de dev).

Usage :
    .venv/bin/python tests/browser/capture_apps.py [--output /tmp/hub-shots] [--webp]

Les URLs ci-dessous sont les adresses locales des conteneurs sur le VPS
(sources : `docker ps`). Adapter la liste si le catalogue évolue.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright

APPLICATIONS = {
    "fortiupgrade": "http://127.0.0.1:8000/",
    "fortiflow": "http://127.0.0.1:13737/",
    "fortiflow2": "http://127.0.0.1:13738/",
    "fortianonymous": "http://127.0.0.1:13742/",
    "vysion": "http://127.0.0.1:8080/",
}

VIEWPORT = {"width": 1440, "height": 900}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="/tmp/hub-shots")
    parser.add_argument("--webp", action="store_true", help="convertir en WebP (léger)")
    args = parser.parse_args()

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(viewport=VIEWPORT, device_scale_factor=1, locale="fr-FR")
        for slug, url in APPLICATIONS.items():
            page = context.new_page()
            try:
                page.goto(url, wait_until="networkidle", timeout=25000)
            except Exception as error:  # noqa: BLE001 — capture best effort
                print(f"{slug}: navigation incomplète ({type(error).__name__})")
            page.wait_for_timeout(1500)
            target = output / f"{slug}.png"
            page.screenshot(path=str(target))
            print(f"{slug}: {page.title()[:60]!r} -> {target}")
            page.close()
        browser.close()

    if args.webp:
        from PIL import Image

        for png in sorted(output.glob("*.png")):
            with Image.open(png) as image:
                image.save(png.with_suffix(".webp"), "WEBP", quality=82, method=6)
            print(f"WebP: {png.with_suffix('.webp')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
