# SNS Hub — État du projet

Dernière mise à jour : 2026-09-16 (UTC)
Statut : **implementation** — application, helper certificat et tests terminés ;
déploiement en cours.

> Ce fichier est le point de reprise opérationnel du projet. Il reflète l'état
> **réel** (Git, runtime, tests) et doit être mis à jour à chaque étape majeure.
> Les décisions structurantes sont dans `docs/decisions.md`.

## Mission

SNS Hub est le point d'entrée unique vers les webapps internes SNS :

- URL de production : `https://hub.valdev.me`
- Workspace canonique : `/home/tetrax/workspace/hub`
- Repository : `https://github.com/Tetrax/hub`

## Avancement (journal de reprise)

- [x] **Phase 0 — Audit initial** (2026-09-16)
      Workspace vide, aucun fichier préexistant à préserver. Repository GitHub
      `Tetrax/hub` public et vide. Rien à écraser.
- [x] **Phase 1 — Audit de l'environnement** (2026-09-16)
      Faits vérifiés : nginx hôte avec allowlist IP globale
      (`/etc/nginx/conf.d/00-application-access.conf`), sites par domaine avec
      certificats Let's Encrypt dédiés, ACME via webroot punché par location
      dédiée, certbot sous lock infra partagé. Applications déployées :
      FortiUpgrade (`:8000`), FortiFlow (`:13737`), FortiFlow2 (`:13738`),
      Scout (`:13741`), FortiAnonymous (`:13742`), JOX (`:13743`), Vysion (`:8080`),
      Portainer (`:9443`). FortiUpgrade fournit le mécanisme autoritatif de
      gestion des certificats : analysé et repris comme modèle. DA SNS :
      palette `#0B0B0D`, `#141417`, `#F4A8C9`, `#FED2F2`, assets réels
      `logo-pink.png` + `panther.jpg`.
- [x] **Phase 2 — Architecture & context-first**
      `AGENTS.md`, `README.md`, `docs/*` : rédaction initiale faite ; mise à jour
      finale après déploiement.
- [x] **Phase 3 — Développement**
      Application Flask (landing page SNS, admin CRUD, gestion du certificat TLS
      via helper root) + helper privilégié (`helper/`) + outillage de déploiement
      (`deploy/`, `scripts/`).
- [x] **Phase 4 — Tests locaux**
      Suite pytest : **127 tests / 127 passés** (`python -m pytest`).
      Unitaires (validation URLs/slugs/uploads, certificats, protocole), intégration
      (app + helper réel via socket Unix), sécurité (en-têtes, CSRF, proxy de
      confiance, XSS, path traversal, verrouillage brute force).
      Restent à faire : recette navigateur réelle sur la production.
- [ ] **Phase 5 — Git** (commits locaux en cours ; push et vérification distante)
- [ ] **Phase 6 — Build Docker & déploiement** (compose canonique, nginx, HTTPS)
- [ ] **Phase 7 — Recette de production** (healthcheck, persistance, restart,
      recréation, certificats, navigateur réel desktop/mobile/admin)
- [ ] **Phase 8 — Documentation finale & Obsidian**
- [ ] **Phase 9 — Rapport final**

## Décisions prises à date

Voir `docs/decisions.md` (D1..D8) : Python 3.12 + Flask SSR + SQLite ; déploiement
compose depuis le dépôt canonique (pas de stack Portainer divergente) ; helper
root + socket Unix + activation atomique + rollback pour les certificats ; admin
mono-compte créé au premier accès ; uploads validés par magic bytes ; catalogue
initial limité aux applications réellement déployées.

## Prochaine action

Déployer : répertoires runtime, build image, compose, nginx + certificat initial
(certbot webroot), activation de la paire gérée, puis recette de production.

## Points ouverts

- Aucun point bloquant à ce stade.
