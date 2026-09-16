# SNS Hub — État du projet

Dernière mise à jour : 2026-09-16 (UTC)
Statut : **implementation** — voir « Avancement » pour la reprise.

> Ce fichier est le point de reprise opérationnel du projet. Il reflète l'état
> **réel** (Git, runtime, tests) et doit être mis à jour à chaque étape majeure.
> Les décisions structurantes sont dans `docs/decisions.md`.

## Mission

SNS Hub est le point d'entrée unique vers les webapps internes SNS :

- URL de production : `https://hub.valdev.me`
- Workspace canonique : `/home/tetrax/workspace/hub`
- Repository : `https://github.com/Tetrax/hub`

Catalogue / launcher administrable : landing page publique avec cartes d'applications
+ administration (`/admin`) pour gérer le catalogue, les screenshots et le
certificat TLS du Hub.

## Avancement (journal de reprise)

- [x] **Phase 0 — Audit initial** (2026-09-16)
      Workspace vide, aucun fichier préexistant à préserver. Repository GitHub
      `Tetrax/hub` public et vide (aucun commit). Rien à écraser.
- [x] **Phase 1 — Audit de l'environnement** (2026-09-16)
      Faits vérifiés : nginx hôte avec allowlist IP globale
      (`/etc/nginx/conf.d/00-application-access.conf`, allowlist = IP SNS + domicile,
      `deny all`), sites par domaine avec certificats Let's Encrypt dédiés,
      ACME via webroot punché par location dédiée, certbot sous lock infra partagé.
      Applications déployées : FortiUpgrade (`:8000`), FortiFlow (`:13737`),
      FortiFlow2 (`:13738`), Scout (`:13741`), FortiAnonymous (`:13742`),
      JOX (`:13743`), Vysion (`:8080`), Portainer (`:9443`).
      FortiUpgrade fournit le mécanisme autoritatif de gestion des certificats
      (helper root + socket Unix + activation atomique + nginx -t/reload + rollback) :
      analysé et repris comme modèle pour Hub.
      DA SNS : palette officielle `#0B0B0D`, `#141417`, `#F4A8C9`, `#FED2F2`,
      assets réels `logo-pink.png` + `panthere.jpg` (issus des projets SNS existants).
- [ ] **Phase 2 — Architecture & context-first** (en cours)
      `AGENTS.md`, `README.md`, `docs/*` : rédaction initiale faite, finalisation
      après implémentation.
- [ ] **Phase 3 — Développement** (application + tests)
- [ ] **Phase 4 — Tests** (unitaires/intégration/sécurité, navigateur réel)
- [ ] **Phase 5 — Git** (commits, push GitHub)
- [ ] **Phase 6 — Build Docker & déploiement** (compose canonique, nginx, HTTPS)
- [ ] **Phase 7 — Recette de production** (healthcheck, persistance, restart,
      recréation, certificats)
- [ ] **Phase 8 — Documentation finale & Obsidian**
- [ ] **Phase 9 — Rapport final**

## Décisions prises à date

Voir `docs/decisions.md` (D1..D8). Résumé : Python 3.12 + Flask SSR + SQLite,
déploiement compose depuis le dépôt canonique (pas de stack Portainer divergente),
gestion des certificats alignée sur le modèle FortiUpgrade (helper root + socket
Unix + activation atomique + rollback), admin mono-compte créé au premier accès
sans mot de passe par défaut.

## Prochaine action

Implémenter l'application Flask (`app/`), le helper certificat (`helper/`) et la
suite de tests, puis valider en local avant build Docker.

## Points ouverts

- Aucun point bloquant à ce stade.
