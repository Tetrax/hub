# SNS Hub

**Tous vos outils. Un seul accès.**

SNS Hub est le portail interne SNS Security : il présente les applications
internes (Fortinet, sécurité, utilitaires) sur une seule page et fournit leur
administration — catalogue, screenshots, ordre, visibilité, statut.

- **Production** : https://hub.valdev.me
- **Administration** : https://hub.valdev.me/admin
- **Dépôt** : https://github.com/Tetrax/hub

Le Hub est un **catalogue / launcher** : il référence les applications et
ouvre leurs URLs ; il ne les proxifie pas, ne les surveille pas et n'exécute
aucune requête vers elles.

## Fonctionnalités

- Landing page légère (rendu serveur, sans framework JS) : cartes avec capture
  réelle, catégorie, statut discret, recherche instantanée et filtre par
  catégorie (fonctionnels sans JavaScript), responsive desktop/tablette/mobile.
- Administration : CRUD des applications, ordre d'affichage, masquage immédiat,
  téléversement de screenshots (PNG/JPEG/WebP, validés par magic bytes),
  paramètres du portail, rotation du mot de passe.
- Gestion du certificat TLS : état complet de la paire active et remplacement
  en deux temps (valider puis activer) avec bascule atomique, `nginx -t`,
  rechargement, vérification du certificat réellement servi et rollback.

## Architecture

```
Nginx (TLS, allowlist IP)  →  conteneur hub-web (gunicorn/Flask, SQLite)
                                    ↕ socket Unix
                            hub-cert-helper (root) → générations TLS atomiques
```

Détails : [`docs/architecture.md`](docs/architecture.md) ·
Exploitation : [`docs/operations.md`](docs/operations.md) ·
Décisions : [`docs/decisions.md`](docs/decisions.md) ·
État : [`docs/state.md`](docs/state.md).

## Développement

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest tests/ -q

# exécution locale (données dans ./runtime/data)
HUB_DATA_DIR=./runtime/data HUB_TLS_HOSTNAME=hub.valdev.me \
  .venv/bin/python -c "from app import create_app; create_app().run(host='127.0.0.1', port=8000)"
```

Recette navigateur (Playwright/Chromium) :

```bash
playwright install chromium   # une seule fois par poste
HUB_BASE_URL=http://127.0.0.1:8000 .venv/bin/python tests/browser/acceptance.py
```

## Déploiement

```bash
./scripts/deploy.sh                     # commit courant → image SHA → conteneur → healthcheck
sudo ./scripts/backup.sh                # sauvegarde base + uploads + certificats
```

Rollback : redéployer l'image du commit précédent
(`HUB_IMAGE_TAG=<sha> docker compose up -d --no-build`), données persistantes
compatibles (voir `docs/operations.md`).

## Sécurité

Sessions serveur (cookie HttpOnly/Secure/SameSite=Strict, jeton haché), scrypt,
CSRF, contrôle d'origine, verrouillage anti-brute-force, en-têtes de sécurité,
CSP stricte, conteneur en lecture seule non-root, clé privée 0600 root jamais
exposée, aucune requête sortante vers le catalogue.
