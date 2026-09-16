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
- Catégories administrables (V1.1) : entité en base avec usage, ordre d'affichage,
  renommage, création rapide depuis le formulaire d'une application et
  suppression sûre (réassignation obligatoire ; repli « Autres » protégé). Les
  filtres du portail en découlent automatiquement.
- Thème clair / sombre (V1.1) : bascule discrète sur le portail et dans
  l'administration, choix mémorisé par navigateur, préférence système respectée
  à la première visite, aucun flash au chargement. La direction artistique
  sombre reste la référence.
- Gestion du certificat TLS : état complet de la paire active et remplacement
  en deux temps (valider puis activer) avec bascule atomique, `nginx -t`,
  rechargement, vérification du certificat réellement servi et rollback.
- Import de certificats (V1.2) : **PKCS#12 / PFX** (`.p12`, `.pfx`, mot de passe
  optionnel) lu en mémoire par l'application — un seul fichier à fournir, la
  chaîne et le certificat feuille sont extraits automatiquement (racine omise),
  le secret n'est jamais conservé ; mode **PEM / CRT avancé** conservé, avec
  détection réelle **DER**. Même pipeline de validation/activation que la V1.
- Portabilité (V1.3) : le **même dépôt** se déploie sur le VPS (Nginx + helper +
  Certbot) ou sur n'importe quelle VM Linux avec Docker — y compris **derrière
  un reverse proxy d'entreprise** (TLS géré en amont) et **sans Nginx, sans
  Certbot, sans helper**. `compose.yaml` est générique, `compose.vps.yaml` porte
  les spécificités du VPS, `.env` la configuration locale (`HUB_BIND_IP`,
  `HUB_PORT`, `HUB_UID/GID`, `HUB_TRUSTED_PROXY_CIDRS`…).

## Architecture

```
Profil VPS        : Nginx (TLS, allowlist IP) → conteneur hub-web (SQLite)
                                            ↕ socket Unix
                                          hub-cert-helper (root)
Profil générique  : proxy/LB d'entreprise (TLS) → conteneur hub-web (SQLite)
                    (aucun Nginx, aucun helper sur l'hôte)
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

Installation sur une nouvelle VM (Docker + Compose, sans Nginx/Certbot/helper) :

```bash
git clone https://github.com/Tetrax/hub && cd hub
cp .env.example .env                    # ajuster HUB_BIND_IP, HUB_PORT, HUB_UID/GID…
sudo scripts/prepare-data-dir.sh        # propriétaire du répertoire de données
docker compose up -d --build
curl -s http://127.0.0.1:13744/healthz  # {"status":"ok","version":"1.3.0",…}
```

Sur le VPS, `.env` porte `COMPOSE_FILE=compose.yaml:compose.vps.yaml` : les
spécificités locales (sous-réseau fixé, proxy de confiance, hostname, socket du
helper) viennent de la surcharge versionnée. Variantes (proxy d'entreprise,
Portainer, hors ligne, restauration) : [`docs/operations.md`](docs/operations.md) §9–§12.

Rollback : redéployer l'image du commit précédent
(`HUB_IMAGE_TAG=<sha> docker compose up -d --no-build`), données persistantes
compatibles (voir `docs/operations.md`).

## Sécurité

Sessions serveur (cookie HttpOnly/Secure/SameSite=Strict, jeton haché), scrypt,
CSRF, contrôle d'origine, verrouillage anti-brute-force, en-têtes de sécurité,
CSP stricte, conteneur en lecture seule non-root, clé privée 0600 root jamais
exposée, aucune requête sortante vers le catalogue.
