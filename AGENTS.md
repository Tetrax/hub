# SNS Hub — contexte projet (agents)

Ce document est destiné à tout agent (ou développeur) qui reprend le projet :
tout ce qui est nécessaire pour comprendre et faire évoluer SNS Hub sans
reconstituer l'historique.

## Produit

SNS Hub est le **point d'entrée unique des applications internes SNS** :
une landing page qui présente les applications et une administration
(`/admin`) qui gère le catalogue, les screenshots, le certificat TLS du Hub,
et — depuis la V1.6/V1.6.2 — la **surveillance de l'image** (rapport Trivy de la
CI) avec ses **alertes email** (transport SMTP ou Microsoft 365 configurable) et
ses **secrets administrables** (jeton GitHub, mot de passe SMTP, secret client
Microsoft 365 — saisis dans la webapp, l'environnement ne servant que de
bootstrap).
C'est un **launcher, pas un proxy** : il n'exécute, ne proxifie, ne surveille
aucune application référencée.

- **URL de production** : `https://hub.valdev.me`
- **Workspace canonique** : `/home/tetrax/workspace/hub` (source unique de vérité)
- **Repository** : `https://github.com/Tetrax/hub`
- **Image** : `hub:<git-sha>` (labels OCI source/revision/created)
- **Conteneur** : `hub-web` (Compose projet `hub`), bind `127.0.0.1:13744` → 8000
- **Trois packagings** : VPS (`compose.yaml` + `compose.vps.yaml`, Nginx + helper),
  générique (proxy externe), **standalone Portainer** (`compose.standalone.yaml` :
  un conteneur qui sert HTTPS directement, certificat géré depuis la page web ;
  rattachement optionnel à un réseau Docker existant + IPv4 statique par variables)

## Stack

Python 3.12 + Flask 3.1 (rendu serveur Jinja2) + gunicorn, SQLite (WAL),
CSS/JS faits main (pas de framework frontend), Docker Compose.

## Architecture en bref

- `app/` — l'application web (landing, admin, client du helper certificat).
- `helper/` — helper **root** d'activation des certificats (service systemd
  durci, socket Unix, validation complète, bascule atomique, `nginx -t`,
  reload, vérification du certificat servi, rollback). **Optionnel** : sans lui
  (ou avec `HUB_CERT_RELOAD_NGINX=0`), le reste du Hub fonctionne et la page
  Certificats signale l'indisponibilité.
- `deploy/` — fichiers d'infrastructure versionnés (unit systemd, env exemple,
  vhost Nginx du VPS, **exemple Nginx générique**, hook certbot).
- `compose.yaml` (générique) + `compose.vps.yaml` (surcharge du VPS) + `.env`
  (local, non versionné) : toute la configuration d'infrastructure. Le mode
  standalone utilise son propre fichier autonome `compose.standalone.yaml`
  (Portainer ne gère qu'un seul fichier Compose).
- `scripts/` — build, deploy, backup, install-helper, prepare-data-dir,
  save/load-image (hors ligne).
- `tests/` — pytest (unitaires/intégration/sécurité/portabilité) + recette
  navigateur + recettes hôte dans `tests/vm/`.
- `docs/` — architecture, décisions, état, exploitation.

Détails : `docs/architecture.md`.

## Composants et responsabilités uniques

| Responsabilité | Mécanisme autoritatif |
|---|---|
| Catalogue (CRUD, ordre, visibilité) | `app/views_admin.py` + `app/catalog.py` |
| Catégories (CRUD, ordre, réassignation) | `app/catalog.py` (`categories`) |
| Migration de schéma (`user_version`) | `app/db.py` (`init_db`) |
| Thème clair/sombre (tokens, bascule) | `app/static/css/hub.css` + `theme-init.js`/`hub.js` |
| Vues du catalogue (Cartes/Liste, préférence) | `app/templates/index.html` + `hub.js` + `catalog-view-init.js` + `hub.css` |
| Branding du header (libellé) | `app/config.py` (`HUB_BRAND_LABEL`) + `app/templates/base.html` |
| Contrôle de sécurité de l'image (CI) | `.github/workflows/ci.yml` (Trivy, informatif) + `scripts/trivy_report.py` (résumé) |
| Surveillance de l'image (Trivy → Hub) | `app/trivy_monitor.py` (état, baseline, delta, verrou) + `app/trivy.py` (validation) + `app/trivy_github.py` (API GitHub) + `app/trivy_scheduler.py` |
| Transport email (SMTP / Microsoft 365) | `app/trivy_email.py` (point d'envoi unique + composition) + `app/graphmail.py` (Graph, client credentials) |
| Secrets administrables (stockage, provenance) | `app/secretstore.py` (fichiers 0600 du répertoire de données ; admin prioritaire, env en bootstrap) : jeton GitHub, mot de passe SMTP, secret client Microsoft 365 |
| Section admin Sécurité / Alertes | `app/views_security.py` + `app/templates/admin/security.html` |
| Screenshots (validation, stockage) | `app/uploads.py` (magic bytes, noms uuid) |
| Authentification admin | `app/auth.py` (scrypt, sessions SQLite, CSRF, verrouillage) |
| En-têtes de sécurité / frontière proxy | `app/security.py` |
| Validation des URLs du catalogue | `app/urls.py` |
| Choix du backend certificat | `app/certbackend.py` (`helper` \| `local` \| `none`) |
| Dialogue app ↔ helper (VPS) | `app/certclient.py` + `app/hub_cert_protocol.py` |
| TLS direct du conteneur (standalone) | `app/certlocal.py` (activation + `SIGHUP` + vérification servie + bootstrap) |
| Lecture des bundles certificat (PKCS#12/PFX, DER) | `app/certparse.py` (en mémoire) |
| Validation/activation TLS | `helper/hub_certctl.py` (une seule implémentation, utilisée par le helper **et** par le standalone) |
| Service privilégié | `helper/hub_cert_helper.py` + `deploy/hub-cert-helper.service` |
| Amorçage TLS du standalone | `app/standalone/entrypoint.sh` (transparent hors standalone) + `bootstrap_certificate` |
| Déploiement | `compose.yaml` (générique) + `compose.vps.yaml` (surcharge) + `compose.standalone.yaml` (Portainer) + `scripts/build.sh` + `scripts/deploy.sh` |

Ne pas créer un second chemin pour une responsabilité déjà couverte (par
exemple : installer un certificat sans passer par `hub_certctl`, ou écrire
directement dans `/var/lib/hub/certificates/active`).

## Données et persistance

- répertoire de données = `HUB_DATA_PATH` (défaut `./runtime/data`) :
  `hub.sqlite` (catalogue, catégories, sessions, admin, verrouillages, réglages
  de la surveillance et transport email non sensible),
  `uploads/` (screenshots, noms `uuid.webp|png|jpg`),
  `secrets/` (secrets administrés : `github-token`, `smtp-password`,
  `microsoft365-client-secret` — répertoire 0700, fichiers 0600, écriture
  atomique, jamais en base ni rendus),
  `.secret_key` (signature des sessions, 0600) ;
- `/var/lib/hub/certificates/` (générations TLS + lien `active`, root-only).

En **standalone**, tout vit dans des volumes Docker nommés, initialisés depuis
l'image avec les droits de l'utilisateur applicatif (uid 1000) : `hub_data`
(→ `/data`) et `hub_certs` (→ `/certs` : générations, lien `active`, paire
active, marqueur `.bootstrap`). Aucun `mkdir`/`chown` sur l'hôte.

`runtime/` est **hors Git**. Le répertoire de données doit appartenir à
`HUB_UID:HUB_GID` (`sudo scripts/prepare-data-dir.sh`), sinon le démarrage
échoue avec un message explicite. Le conteneur tourne en lecture seule ; seuls
`/data` (bind mount) et `/tmp` (tmpfs) sont inscriptibles.

## Docker

- `compose.yaml` est **canonique, générique et portable** : aucune valeur propre
  à une machine, tout par variables (`HUB_BIND_IP`, `HUB_PORT`, `HUB_UID/GID`,
  `HUB_DATA_PATH`, `HUB_TRUSTED_PROXY_CIDRS`, `HUB_TLS_HOSTNAME`,
  `HUB_CONTAINER_NAME`, `HUB_IMAGE_TAG`) avec défauts sûrs. Pas de sous-réseau
  imposé (réseau Docker automatique).
- `compose.vps.yaml` est la **surcharge du VPS** (sous-réseau fixé
  `172.31.244.0/24`, gateway `172.31.244.1` comme seul proxy de confiance,
  hostname, socket helper). `COMPOSE_FILE` (dans `.env`) sélectionne les
  fichiers : `compose.yaml` seul (générique) ou
  `compose.yaml:compose.vps.yaml` (VPS).
- Le build part de la racine du dépôt ; pas de clone de production, pas de stack
  Portainer dupliquée non versionnée (Portainer déploie le même `compose.yaml`).
- Le build injecte `HUB_GIT_SHA` (affiché dans l'admin) et les labels OCI.

## Nginx

Site dédié `/etc/nginx/sites-available/hub.valdev.me` (copie de référence dans
`deploy/nginx/`). `deploy/nginx/hub-generic.conf.example` est l'exemple **portable** (placeholders
HOSTNAME/UPSTREAM/CERT_PATH/KEY_PATH, sans Certbot ni allowlist) ; le vhost du
VPS reste la référence de production. L'allowlist IP globale du VPS est
**incluse** (pas recopiée) ;
le loopback est autorisé pour les vérifications sur le VPS. TLS servi depuis
`/var/lib/hub/certificates/active/`. Toute modification Nginx passe par
`nginx -t` puis reload, sous le verrou infra partagé quand on touche à
l'infrastructure partagée.

## Commandes importantes

```bash
./scripts/deploy.sh                     # déploiement (commit poussé requis)
gh workflow run ci.yml                   # scan de sécurité manuel (GitHub Actions)
docker compose exec web python -m app.manage seed   # catalogue initial (installation neuve)
bash tests/vm/standalone-check.sh       # recette standalone TLS direct (isolée)
sudo ./scripts/backup.sh                # sauvegarde complète
sudo scripts/prepare-data-dir.sh        # propriétaire du répertoire de données
sudo scripts/install-helper.sh          # (ré)installation du helper cert root
.venv/bin/python -m pytest tests/ -q    # suite de tests
bash tests/vm/generic-vm-check.sh       # recette « nouvelle VM » (isolée)
sudo bash tests/vm/helper-check.sh      # helper avec/sans Nginx (bac à sable)
docker compose logs -f web              # logs applicatifs
docker compose exec web python -m app.manage reset-admin
```

## Tests

- `tests/` : 571 tests pytest (validation d'entrées, uploads, auth, CRUD,
  catégories, migration, thème, branding (`HUB_BRAND_LABEL`), vues du catalogue
  (Cartes/Liste), bundles PKCS#12/PFX et DER, landing, sécurité,
  certificats/rollback, intégration app ↔ helper par socket, configuration de
  déploiement : Compose générique/surcharge, durcissement systemd, portabilité,
  rendu du rapport Trivy et invariants de la CI, surveillance Trivy
  (baseline/delta/pannes), **secrets administrables et transport email
  (V1.6.1/V1.6.2)** : stockage des secrets (`test_secretstore.py`), Microsoft
  Graph simulé (`test_graph_email.py`), SMTP réel factice + bascule de transport
  (`test_trivy_email.py`), UI, CSRF et jeton GitHub (`test_security_admin.py`),
  migration V1.6 et résolution du jeton (`test_trivy_monitor.py`)).
- `.github/workflows/ci.yml` : job `tests` (pytest, bloquant) puis job
  `security-scan` (Trivy **informatif** sur l'image réelle — HIGH/CRITICAL
  corrigibles, artefact `trivy-report`, scan quotidien de `main` à 05:23 UTC,
  lancement manuel `gh workflow run ci.yml`) ; politique et exploitation dans
  `docs/operations.md` §15, décision D21.
- `tests/browser/acceptance.py` : recette navigateur réelle (desktop, mobile,
  admin, thèmes, vues Cartes/Liste) via Playwright.
- `tests/browser/capture_apps.py` : captures des applications pour le catalogue.
- `tests/vm/generic-vm-check.sh` : recette « VM générique » isolée (projet
  Compose jetable, sans Nginx/Certbot/helper) — healthcheck, landing, admin,
  CRUD, uploads, catégories, paramètres, page certificats, réseau, UID/GID,
  en-têtes de proxy.
- `tests/vm/standalone-check.sh` : recette du déploiement `compose.standalone.yaml`
  (volumes vierges, certificat temporaire, import PKCS#12, activation, certificat
  réellement servi, persistance, refus hors domaine, isolation) ; avec
  `STANDALONE_CHECK_BROWSER=1`, la recette navigateur y est rejouée.
- `tests/vm/helper-check.sh` : activation du helper **sans Nginx**
  (`HUB_CERT_RELOAD_NGINX=0`), refus propre + absence de bascule en mode
  `reload=1` sans Nginx, socket + `SO_PEERCRED`, unité systemd.

## Règles Git

- Commits focalisés, en français, impératif (« feat: … »), historique lisible.
- Le commit déployé doit exister sur `origin/main` (vérifié par `deploy.sh`).
- Ne pas versionner : secrets, `runtime/`, `.env`, certificats, base, logs.
- Ne pas réécrire l'historique, pas de force push.

## Contraintes de sécurité à préserver

- Clé privée : jamais dans Git/l'image/les logs/réponses HTTP ; 0600 root sur le
  VPS, 0600 utilisateur applicatif dans `hub_certs` en standalone ; jamais
  exposée hors du volume
- Secrets administrables (jeton GitHub, mot de passe SMTP, secret client
  Microsoft 365) : jamais en base, jamais dans une réponse HTTP (provenance
  affichée seulement), jamais dans un log ni un traceback ; fichiers 0600 dans
  `secrets/` du répertoire de données ; le secret administré est prioritaire,
  l'environnement (`HUB_GITHUB_TOKEN`, `HUB_SMTP_PASSWORD`,
  `HUB_MICROSOFT_CLIENT_SECRET`) n'est qu'un bootstrap — ne jamais copier un
  secret d'une source vers l'autre.
- Aucune requête serveur vers les URLs du catalogue (pas de SSRF). L'hôte SMTP
  configurable est le seul appel sortant piloté par l'admin : nom d'hôte
  uniquement (jamais une URL), port borné ; les endpoints Graph sont figés.
- Uploads : validation par magic bytes, taille bornée, noms générés.
- En-têtes de sécurité applicatifs maintenus ; CSP stricte (pas d'inline).
- Frontière proxy explicite (`HUB_TRUSTED_PROXY_CIDRS`).

## Zones à ne pas modifier sans raison

- `helper/hub_certctl.py` (invariants d'activation et de rollback) ;
- `deploy/hub-cert-helper.service` (durcissement systemd — l'absence de
  `Requires=nginx.service` et les chemins Nginx préfixés `-` sont **volontaires**) ;
- `compose.yaml` (durcissement du conteneur, points de montage) et
  `compose.vps.yaml` (sous-réseau, proxy de confiance du VPS) ;
- l'ordre des règles d'accès dans le vhost Nginx (loopback puis allowlist) ;
- `compose.standalone.yaml` : **un seul service applicatif** et aucun proxy — le
  conteneur termine lui-même TLS (voir D16) ; `app/certlocal.py` n'envoie jamais
  de signal à un processus non identifié par le fichier PID du serveur ;
- `.github/workflows/ci.yml` : le scan Trivy est **informatif** (`exit-code: 0`)
  — un finding ne doit pas casser la CI (politique assumée, voir D21) ; Trivy
  n'est jamais installé dans l'image, le runtime, le VPS ou Portainer.

## Conventions

- Français pour l'UI, la documentation et les commits ; identifiants en anglais.
- Pas de framework CSS/JS ; progressive enhancement (le site fonctionne sans JS).
- Styles : palette SNS (`#0B0B0D`, `#141417`, `#F4A8C9`, `#FED2F2`, `#ECECEE`),
  **uniquement** via les tokens de `hub.css` (thème sombre = valeurs par défaut,
  thème clair = second jeu, les deux blocs clairs doivent rester identiques).
- Catégories : entité en base (`categories`), jamais de texte libre dans `apps` ;
  le repli « Autres » est protégé (ni suppression ni renommage).
- Catalogue : deux rendus serveur (Cartes par défaut, Liste dense sans captures)
  portent les mêmes attributs `data-*` ; le moteur de recherche/filtre reste
  unique (`hub.js`) et seul le décompte suit la vue affichée.
- Branding : `HUB_BRAND_LABEL` est un libellé purement visuel (validé, borné,
  échappé) — jamais une entrée qui influence hostname, TLS, base ou sessions.
- Erreurs : messages compréhensibles côté UI, détails uniquement dans les logs.

## Principe directeur

**Minimum sufficient change** : corriger le mécanisme autoritatif existant,
sans refonte cosmétique ni abstraction anticipée. Vérifier le comportement réel
(tests + recette) avant de considérer un changement terminé.
