# SNS Hub — État du projet

Dernière mise à jour : 2026-09-16 (UTC)
Statut : **déployé en production** — documentation et clôture en cours.

> Ce fichier est le point de reprise opérationnel du projet. Il reflète l'état
> **réel** (Git, runtime, tests) et doit être mis à jour à chaque étape majeure.
> Les décisions structurantes sont dans `docs/decisions.md`.

## Mission

SNS Hub est le point d'entrée unique vers les webapps internes SNS :

- URL de production : `https://hub.valdev.me`
- Workspace canonique : `/home/tetrax/workspace/hub`
- Repository : `https://github.com/Tetrax/hub`

## Avancement (journal de reprise)

- [x] **Phase 0 — Audit initial** : workspace vide ; repository `Tetrax/hub` vide.
- [x] **Phase 1 — Audit de l'environnement** : nginx + allowlist IP globale,
      certificats Let's Encrypt par domaine, mecanisme certificat FortiUpgrade
      analysé et repris comme modèle ; applications déployées identifiées ;
      DA SNS (`#0B0B0D`/`#F4A8C9`/`#FED2F2`) et assets réels (logo, panthère).
- [x] **Phase 2 — Architecture & context-first** : `AGENTS.md`, `README.md`,
      `docs/architecture.md`, `docs/decisions.md` (D1–D10), `docs/state.md`,
      `docs/operations.md`.
- [x] **Phase 3 — Développement** : application Flask (landing, admin, certificats),
      helper root (`helper/`), outillage (`deploy/`, `scripts/`).
- [x] **Phase 4 — Tests locaux** : **127 tests pytest / 127 passés**.
- [x] **Phase 5 — Git** : commits focalisés, poussés ; `HEAD == origin/main`.
- [x] **Phase 6 — Build & déploiement** :
      helper installé (`hub-cert-helper.service` actif, socket opérationnelle) ;
      image `hub:<sha>` (labels OCI) ; conteneur `hub-web` healthy sur
      `127.0.0.1:13744` ; vhost Nginx `hub.valdev.me` (80 redirection + ACME,
      443 proxy TLS) ; certificat Let's Encrypt émis (expire le **2026-12-15**)
      puis amorcé dans la paire gérée (`/var/lib/hub/certificates/active`) ;
      hook certbot installé.
- [x] **Phase 7 — Recette de production** (2026-09-16) :
      - HTTPS réel : `GET /` → 200, `GET /admin` → 308 puis 200, `/healthz` → 200 ;
      - certificat servi = paire gérée (empreintes SHA-256 identiques) ;
      - en-têtes de sécurité présents (CSP, HSTS, X-Frame-Options…) ;
      - **15/15 vérifications navigateur** (desktop 1440×900, mobile 390×844,
        admin : connexion, CRUD, masquage/réaffichage, logout) ;
      - **5 screenshots réels** téléversés via l'admin (WebP, page 358 Ko) ;
      - **remplacement de certificat réel** via l'admin (valider → activer →
        nginx -t → reload → vérification) : OK, nouvelle génération créée ;
      - renouvellement : `certbot renew --dry-run` OK ; hook de déploiement
        exécuté à la main → nouvelle génération + Nginx sert la paire gérée ;
      - persistance : **restart** (session + données intactes), **recréation**
        `down`/`up` depuis le Compose canonique (5 apps, 5 uploads, admin) ;
      - sauvegarde complète (base + uploads + clé + certificats) restaurée et
        vérifiée (`PRAGMA integrity_check` = ok).
- [ ] **Phase 8 — Documentation finale & Obsidian** (en cours)
- [ ] **Phase 9 — Rapport final**

## État Git

- Branche `main`, poussée sur `origin` ; working tree propre au dernier commit
  (voir `git log` pour le SHA déployé).
- Image déployée : `hub:<SHA>` — le SHA est affiché dans `/admin` (Paramètres)
  et vérifiable par `docker inspect hub-web`.

## Points ouverts

- Compte administrateur de recette : supprimé en fin de mission pour que
  Tetrax crée lui-même son compte via la « Première configuration »
  (`https://hub.valdev.me/admin`). À défaut, mécanisme de secours :
  `docker compose exec web python -m app.manage reset-admin`.
- Sauvegarde : premier passage manuel effectué ; la planification (timer/cron)
  reste à décider par Tetrax.
- Firewall fournisseur : aucune modification nécessaire (l'accès externe à
  `hub.valdev.me` suit l'allowlist existante du VPS).
