# SNS Hub — contexte projet (agents)

Ce document est destiné à tout agent (ou développeur) qui reprend le projet :
tout ce qui est nécessaire pour comprendre et faire évoluer SNS Hub sans
reconstituer l'historique.

## Produit

SNS Hub est le **point d'entrée unique des applications internes SNS** :
une landing page qui présente les applications et une administration
(`/admin`) qui gère le catalogue, les screenshots et le certificat TLS du Hub.
C'est un **launcher, pas un proxy** : il n'exécute, ne proxifie, ne surveille
aucune application référencée.

- **URL de production** : `https://hub.valdev.me`
- **Workspace canonique** : `/home/tetrax/workspace/hub` (source unique de vérité)
- **Repository** : `https://github.com/Tetrax/hub`
- **Image** : `hub:<git-sha>` (labels OCI source/revision/created)
- **Conteneur** : `hub-web` (Compose projet `hub`), bind `127.0.0.1:13744` → 8000

## Stack

Python 3.12 + Flask 3.1 (rendu serveur Jinja2) + gunicorn, SQLite (WAL),
CSS/JS faits main (pas de framework frontend), Docker Compose.

## Architecture en bref

- `app/` — l'application web (landing, admin, client du helper certificat).
- `helper/` — helper **root** d'activation des certificats (service systemd
  durci, socket Unix, validation complète, bascule atomique, `nginx -t`,
  reload, vérification du certificat servi, rollback).
- `deploy/` — fichiers d'infrastructure versionnés (unit systemd, env exemple,
  vhost Nginx de référence, hook certbot).
- `scripts/` — build, deploy, backup, install-helper.
- `tests/` — pytest (unitaires/intégration/sécurité) + recette navigateur.
- `docs/` — architecture, décisions, état, exploitation.

Détails : `docs/architecture.md`.

## Composants et responsabilités uniques

| Responsabilité | Mécanisme autoritatif |
|---|---|
| Catalogue (CRUD, ordre, visibilité) | `app/views_admin.py` + `app/catalog.py` |
| Catégories (CRUD, ordre, réassignation) | `app/catalog.py` (`categories`) |
| Migration de schéma (`user_version`) | `app/db.py` (`init_db`) |
| Thème clair/sombre (tokens, bascule) | `app/static/css/hub.css` + `theme-init.js`/`hub.js` |
| Screenshots (validation, stockage) | `app/uploads.py` (magic bytes, noms uuid) |
| Authentification admin | `app/auth.py` (scrypt, sessions SQLite, CSRF, verrouillage) |
| En-têtes de sécurité / frontière proxy | `app/security.py` |
| Validation des URLs du catalogue | `app/urls.py` |
| Dialogue app ↔ certificats | `app/certclient.py` + `app/hub_cert_protocol.py` |
| Validation/activation TLS | `helper/hub_certctl.py` (une seule implémentation) |
| Service privilégié | `helper/hub_cert_helper.py` + `deploy/hub-cert-helper.service` |
| Déploiement | `compose.yaml` + `scripts/build.sh` + `scripts/deploy.sh` |

Ne pas créer un second chemin pour une responsabilité déjà couverte (par
exemple : installer un certificat sans passer par `hub_certctl`, ou écrire
directement dans `/var/lib/hub/certificates/active`).

## Données et persistance

- `runtime/data/hub.sqlite` (catalogue, catégories, sessions, admin, verrouillages) ;
- `runtime/data/uploads/` (screenshots, noms `uuid.webp|png|jpg`) ;
- `runtime/data/.secret_key` (signature des sessions, 0600) ;
- `/var/lib/hub/certificates/` (générations TLS + lien `active`, root-only).

`runtime/` est **hors Git**. Le conteneur tourne en lecture seule ; seuls
`/data` (bind mount) et `/tmp` (tmpfs) sont inscriptibles.

## Docker

- `compose.yaml` est **canonique** (dépôt = source de vérité) ; le build part de
  la racine du dépôt. Pas de second Compose, pas de clone de production, pas de
  stack Portainer dupliquée (Portainer reste un outil d'observation).
- Sous-réseau fixé `172.31.244.0/24` : le gateway `172.31.244.1` est le seul
  proxy de confiance (variable `HUB_TRUSTED_PROXY_CIDRS`).
- Le build injecte `HUB_GIT_SHA` (affiché dans l'admin) et les labels OCI.

## Nginx

Site dédié `/etc/nginx/sites-available/hub.valdev.me` (copie de référence dans
`deploy/nginx/`). L'allowlist IP globale du VPS est **incluse** (pas recopiée) ;
le loopback est autorisé pour les vérifications sur le VPS. TLS servi depuis
`/var/lib/hub/certificates/active/`. Toute modification Nginx passe par
`nginx -t` puis reload, sous le verrou infra partagé quand on touche à
l'infrastructure partagée.

## Commandes importantes

```bash
./scripts/deploy.sh                     # déploiement (commit poussé requis)
sudo ./scripts/backup.sh                # sauvegarde complète
sudo scripts/install-helper.sh          # (ré)installation du helper cert root
.venv/bin/python -m pytest tests/ -q    # suite de tests
docker compose logs -f web              # logs applicatifs
docker compose exec web python -m app.manage reset-admin
```

## Tests

- `tests/` : 171 tests pytest (validation d'entrées, uploads, auth, CRUD,
  catégories, migration, thème, landing, sécurité, certificats/rollback,
  intégration app ↔ helper par socket).
- `tests/browser/acceptance.py` : recette navigateur réelle (desktop, mobile,
  admin) via Playwright.
- `tests/browser/capture_apps.py` : captures des applications pour le catalogue.

## Règles Git

- Commits focalisés, en français, impératif (« feat: … »), historique lisible.
- Le commit déployé doit exister sur `origin/main` (vérifié par `deploy.sh`).
- Ne pas versionner : secrets, `runtime/`, `.env`, certificats, base, logs.
- Ne pas réécrire l'historique, pas de force push.

## Contraintes de sécurité à préserver

- Clé privée : jamais dans Git/l'image/les logs/réponses HTTP ; 0600 root ;
  jamais montée dans le conteneur.
- Aucune requête serveur vers les URLs du catalogue (pas de SSRF).
- Uploads : validation par magic bytes, taille bornée, noms générés.
- En-têtes de sécurité applicatifs maintenus ; CSP stricte (pas d'inline).
- Frontière proxy explicite (`HUB_TRUSTED_PROXY_CIDRS`).

## Zones à ne pas modifier sans raison

- `helper/hub_certctl.py` (invariants d'activation et de rollback) ;
- `deploy/hub-cert-helper.service` (durcissement systemd) ;
- `compose.yaml` (durcissement du conteneur, sous-réseau, points de montage) ;
- l'ordre des règles d'accès dans le vhost Nginx (loopback puis allowlist).

## Conventions

- Français pour l'UI, la documentation et les commits ; identifiants en anglais.
- Pas de framework CSS/JS ; progressive enhancement (le site fonctionne sans JS).
- Styles : palette SNS (`#0B0B0D`, `#141417`, `#F4A8C9`, `#FED2F2`, `#ECECEE`),
  **uniquement** via les tokens de `hub.css` (thème sombre = valeurs par défaut,
  thème clair = second jeu, les deux blocs clairs doivent rester identiques).
- Catégories : entité en base (`categories`), jamais de texte libre dans `apps` ;
  le repli « Autres » est protégé (ni suppression ni renommage).
- Erreurs : messages compréhensibles côté UI, détails uniquement dans les logs.

## Principe directeur

**Minimum sufficient change** : corriger le mécanisme autoritatif existant,
sans refonte cosmétique ni abstraction anticipée. Vérifier le comportement réel
(tests + recette) avant de considérer un changement terminé.
