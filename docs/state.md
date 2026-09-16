# SNS Hub — État du projet

Dernière mise à jour : 2026-09-16 (UTC)
Statut : **déployé en production, recette passée, passation prête**.

> Ce fichier est le point de reprise opérationnel du projet. Il reflète l'état
> **réel** (Git, runtime, tests) et doit être mis à jour à chaque étape majeure.
> Les décisions structurantes sont dans `docs/decisions.md`.

## Mission

SNS Hub est le point d'entrée unique vers les webapps internes SNS :

- URL de production : `https://hub.valdev.me`
- Workspace canonique : `/home/tetrax/workspace/hub`
- Repository : `https://github.com/Tetrax/hub`

L'image déployée porte exactement le SHA du HEAD du dépôt (règle maintenue par
`scripts/deploy.sh`) : le commit réellement en production se lit donc dans
`git log -1 --format=%H` et dans `/admin` → Paramètres (affiché à l'écran),
et se vérifie par `docker inspect hub-web`.

## Avancement (journal de reprise)

- [x] **Phase 0 — Audit initial** : workspace vide ; repository `Tetrax/hub` vide.
- [x] **Phase 1 — Audit de l'environnement** : nginx + allowlist IP globale,
      certificats Let's Encrypt par domaine, mécanisme certificat FortiUpgrade
      analysé et repris comme modèle ; applications déployées identifiées ;
      DA SNS (`#0B0B0D`/`#F4A8C9`/`#FED2F2`) et assets réels (logo, panthère).
- [x] **Phase 2 — Architecture & context-first** : `AGENTS.md`, `README.md`,
      `docs/architecture.md`, `docs/decisions.md` (D1–D10), `docs/state.md`,
      `docs/operations.md`.
- [x] **Phase 3 — Développement** : application Flask (landing, admin, certificats),
      helper root (`helper/`), outillage (`deploy/`, `scripts/`).
- [x] **Phase 4 — Tests locaux** : **127 tests pytest / 127 passés**.
- [x] **Phase 5 — Git** : commits focalisés poussés ; `HEAD == origin/main`.
- [x] **Phase 6 — Build & déploiement** : helper `hub-cert-helper.service` actif ;
      image `hub:<sha>` (labels OCI) ; conteneur `hub-web` healthy sur
      `127.0.0.1:13744` ; vhost Nginx `hub.valdev.me` (80 : redirection + ACME,
      443 : proxy TLS) ; certificat Let's Encrypt émis (expire le **2026-12-15**)
      puis amorcé dans la paire gérée (`/var/lib/hub/certificates/active`) ;
      hook certbot installé.
- [x] **Phase 7 — Recette de production** (2026-09-16) :
      - HTTPS réel : `GET /` → 200, `GET /admin` → 308/200, `/healthz` → 200 ;
      - certificat servi = paire gérée (empreintes SHA-256 identiques) ;
      - en-têtes de sécurité présents (CSP, HSTS, X-Frame-Options…) ;
      - **15/15 vérifications navigateur** (desktop 1440×900, mobile 390×844,
        admin : connexion, CRUD, upload, masquage/réaffichage, logout) ;
      - **5 screenshots réels** (WebP) téléversés via l'admin — page 358 Ko ;
      - **remplacement de certificat réel** via l'admin (valider → activer →
        `nginx -t` → reload → vérification du certificat servi) : OK ;
      - renouvellement : `certbot renew --dry-run` OK ; hook de déploiement
        exécuté à la main → nouvelle génération + Nginx sert la paire gérée ;
      - persistance : **restart** (session + données intactes) puis **recréation**
        `down`/`up` depuis le Compose canonique (5 apps, 5 uploads, admin) ;
      - sauvegarde complète restaurée et vérifiée (`PRAGMA integrity_check` = ok).
- [x] **Phase 8 — Documentation finale & Obsidian** : documentation complète dans
      le dépôt ; note canonique `01 - Projects/sns-hub.md` créée dans le vault
      (gates `dashboard`/`validate`/`conflicts` passés ; seuls les fichiers de la
      présente mission ont été commités, le reste du vault portant des
      modifications étrangères non commitées).
- [x] **Phase 9 — Passation** : le compte administrateur **de recette** a été
      supprimé ; la « Première configuration » est disponible pour Tetrax sur
      `https://hub.valdev.me/admin`. Aucun mot de passe n'a été transmis,
      stocké ou journalisé.

## État Git

- Branche `main` poussée sur `origin` ; working tree propre.
- Image déployée : `hub:<HEAD>` — vérifiable par
  `docker inspect hub-web --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'`.

## Points ouverts

- Tetrax doit créer le compte administrateur (première configuration) et
  confirmer l'accès depuis une sortie SNS. Mécanisme de secours :
  `docker compose exec web python -m app.manage reset-admin`.
- Planification de `sudo scripts/backup.sh` (timer système) à décider — la
  sauvegarde fonctionne manuellement et a été testée (restauration incluse).
- Firewall fournisseur : aucune modification nécessaire (l'accès externe à
  `hub.valdev.me` suit l'allowlist existante du VPS).
