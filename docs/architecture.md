# SNS Hub — Architecture

## En une phrase

SNS Hub est un catalogue / launcher : une application web (Flask, rendu serveur)
qui liste les applications internes SNS et propose une administration
(catalogue, screenshots, certificat TLS). Il n'exécute, ne proxifie et ne
surveille aucune des applications qu'il référence.

## Vue d'ensemble

Le code applicatif est **unique** ; seules les briques d'infrastructure
changent selon le déploiement. Deux profils sont supportés par le même dépôt.

**Profil A — VPS de production** (Nginx local + helper + Certbot) :

```
                        Internet / réseau SNS
                                │
                 ┌──────────────▼───────────────┐
                 │  Nginx (hôte)                │
                 │  hub.valdev.me               │
                 │  allowlist IP globale        │
                 │  TLS: paire gérée par Hub    │
                 └──────────────┬───────────────┘
                                │ proxy_pass 127.0.0.1:13744
                 ┌──────────────▼───────────────┐
                 │  Conteneur hub-web           │
                 │  gunicorn + Flask (uid 1000) │
                 │  /data (SQLite + uploads)    │
                 └──────────────┬───────────────┘
                                │ socket Unix (validate/activate/status)
                 ┌──────────────▼───────────────┐
                 │  hub-cert-helper (root)      │
                 │  validation + activation TLS │
                 │  nginx -t / reload / vérif.  │
                 └──────────────────────────────┘
```

**Profil B — VM générique / entreprise** (Docker seul, TLS ailleurs) :

```
        Utilisateur ── HTTPS ──▶ proxy / LB d'entreprise (certificat)
                                        │ HTTP interne
                        ┌───────────────▼──────────────┐
                        │  Conteneur hub-web           │
                        │  gunicorn + Flask (uid 1000) │
                        │  /data (SQLite + uploads)    │
                        └──────────────────────────────┘
                        (pas de Nginx, pas de Certbot,
                         pas de helper : page Certificats
                         signalée « indisponible »)
```

## Déploiement : Compose générique + surcharge + variables

| Élément | Rôle | Où |
|---|---|---|
| `compose.yaml` | déploiement **générique** : durcissement, healthcheck, image, port, données — aucune valeur propre à une machine | versionné |
| `compose.vps.yaml` | **surcharge minimale** du VPS : sous-réseau fixé, proxy de confiance local, hostname, socket du helper | versionné |
| `.env` | valeurs d'installation : `HUB_BIND_IP`, `HUB_PORT`, `HUB_UID/GID`, `HUB_DATA_PATH`, `HUB_TRUSTED_PROXY_CIDRS`, `HUB_TLS_HOSTNAME`, `HUB_BACKUP_DIR`, `COMPOSE_FILE` | local (jamais versionné) |
| `compose.standalone.yaml` | déploiement **standalone** (Portainer) : HTTPS direct, un seul conteneur, volumes nommés, une seule variable obligatoire (`HUB_HOSTNAME`) — réseau Docker existant et IPv4 statique optionnels (D18) | versionné |
| `.env.example` | modèle documenté, sans secret | versionné |

`COMPOSE_FILE` (dans `.env`) sélectionne les fichiers :
`compose.yaml` seul (générique) ou `compose.yaml:compose.vps.yaml` (VPS).

Conséquence directe : le même commit se déploie `git clone` +
`docker compose up -d --build` sur n'importe quelle VM Docker, et
`docker compose -f compose.yaml -f compose.vps.yaml …` sur le VPS. La
configuration effective du VPS est restée **identique** au passage à cette
structure (vérifié par comparaison des rendus `docker compose config`).

## Composants

### 1. Application (`app/`)

- **Flask 3.1** en rendu serveur (Jinja2), sans framework frontend ; CSS et JS
  faits main (un seul fichier CSS, un seul fichier JS de progressive
  enhancement, complété par deux scripts d'initialisation appliqués avant le
  premier rendu : `theme-init.js` pour le thème, `catalog-view-init.js` pour la
  vue du catalogue).
- **gunicorn** (2 workers, 4 threads) sert l'application — en HTTP sur
  `0.0.0.0:8000` derrière Nginx ou un proxy, ou **en HTTPS directement**
  (`HUB_TLS_CERT`/`HUB_TLS_KEY`, port interne 8443 publié en 443) en standalone.
  Le contexte SSL est construit par les workers : un `SIGHUP` du maître les
  redémarre gracieusement et reprend la nouvelle paire, **sans redémarrer le
  conteneur** (voir D16).
- **SQLite** (mode WAL) pour le catalogue, les sessions, le compte admin et les
  tentatives de connexion ; **uploads** de screenshots sur disque. Schéma
  versionné (`PRAGMA user_version`) et migré automatiquement au démarrage.
- Modules : `views_public.py` (landing, images, `/healthz`), `views_admin.py`
  (CRUD catalogue, paramètres, session), `views_cert.py` (parcours certificat),
  `certclient.py` + `hub_cert_protocol.py` (client du helper), `security.py`
  (en-têtes, frontière proxy, origine), `auth.py` (scrypt, sessions, CSRF,
  verrouillage), `uploads.py` (validation par magic bytes), `urls.py`
  (validation d'entrées), `certparse.py` (lecture PKCS#12/PFX et DER, en mémoire),
  `manage.py` (CLI d'exploitation : `seed`, `reset-admin`, `report-orphans`).
  `catalog.py` porte aussi les catégories (CRUD, ordre, réassignation).
  Le parcours certificat passe par **`certbackend.py`** : `certclient.py` (helper
  du VPS), `certlocal.py` (TLS direct du standalone) ou aucun backend — les vues
  ne connaissent que ces trois fonctions.

### 2. Modèle de données

```
categories(id, name, slug UNIQUE NOCASE, position, is_fallback, created_at, updated_at)
apps(id, slug UNIQUE NOCASE, name, description, url, image,
     category_id → categories(id) NOT NULL, position, enabled, status,
     created_at, updated_at)
settings(key, value) · admin_users · sessions · login_attempts · cert_validations
```

- Une application appartient à **une** catégorie (clé étrangère, `NOT NULL`) ;
  une catégorie peut n'être utilisée par aucune application.
- `is_fallback = 1` désigne la catégorie de repli (« Autres ») : non supprimable,
  non renommable ; elle recueille les applications d'une catégorie supprimée.
- Schéma versionné par `PRAGMA user_version` ; migration 1 → 2 transactionnelle
  et idempotente, déclenchée par `db.init_db()` au démarrage : aucune
  application, association, position, image ou visibilité n'est perdue.

### 3. Certificats : `hub_certctl` + trois backends

**`helper/hub_certctl.py` est la seule implémentation** de la validation
(format, dates, SAN/FQDN, clé ↔ certificat, ordre et signatures de chaîne,
chargement TLS réel) et des primitives d'activation (générations immuables
`.active-<hash>`, bascule du lien `active` par `os.replace`, verrou
inter-processus, `restore`, `cleanup_generation`). Elle est utilisée :

- par le **helper root** du VPS (copie installée dans `/opt/hub-cert-helper`) ;
- par le **backend `local`** du standalone (module copié dans l'image
  applicative, CLI `openssl` installée) — aucune duplication de règles.

Backends (`HUB_CERT_BACKEND`) : `helper` (défaut) · `local` (standalone, SIGHUP
du serveur HTTPS + vérification du certificat servi) · `none` (TLS géré en
amont, page informative).

Service systemd `hub-cert-helper.service`, durci (ProtectSystem=strict,
NoNewPrivileges, CapabilityBoundingSet réduit, UMask=0027). Rôle :

- **socket Unix** `/run/hub-cert-helper/helper.sock` (0660 root:tetrax) ;
  vérification du pair par `SO_PEERCRED` (uid/gid 1000 attendus) ;
  opérations `ping`, `status`, `validate`, `activate` ;
- **CLI root** : `install` (amorçage) et `renew` (hook certbot avec
  `RENEWED_LINEAGE`) ;
- **validation complète** avant toute activation : format PEM, dates, SAN/FQDN
  (`openssl x509 -checkhost`), appariement clé↔certificat (clés publiques DER),
  ordre et signature de la chaîne, chargement TLS effectif de la paire normalisée ;
- **activation atomique** : générations immuables `.active-<hash>` + bascule du
  lien `active` par `os.replace`, verrou inter-processus `.certctl.lock` ;
- **vérification de bout en bout** : `nginx -t` → `systemctl reload nginx` →
  contrôle du certificat réellement présenté (empreinte SHA-256 via
  `openssl s_client` avec SNI) → **rollback automatique** (ancienne génération
  restaurée + reload) si une étape échoue.

### 4. Nginx (hôte)

- Site dédié `hub.valdev.me` : port 80 (redirection + `/.well-known/acme-challenge`
  ouvert pour Let's Encrypt), port 443 (proxy inverse + TLS).
- Contrôle d'accès : l'allowlist IP globale
  (`/etc/nginx/conf.d/00-application-access.conf`) est incluse telle quelle dans
  le vhost ; le loopback est ajouté en premier pour permettre les vérifications
  d'exploitation sur le VPS (aucune duplication de la liste).
- `ssl_certificate` / `ssl_certificate_key` pointent sur
  `/var/lib/hub/certificates/active/{fullchain,privkey}.pem` (paire gérée).
- Copie versionnée de référence : `deploy/nginx/hub.valdev.me.conf`.

### 5. Données persistantes

| Donnée | Emplacement hôte | Conteneur | Sauvegarde |
|---|---|---|---|
| Catalogue, sessions, compte admin | `runtime/data/hub.sqlite` | `/data/hub.sqlite` | oui (copie SQLite cohérente) |
| Screenshots | `runtime/data/uploads/` | `/data/uploads/` | oui |
| Clé de signature des sessions | `runtime/data/.secret_key` (0600) | `/data/.secret_key` | oui (sensible) |
| Certificat + clé privée gérés | `/var/lib/hub/certificates/` (root) | non monté dans le conteneur | oui (archive séparée root) |

En **standalone**, les mêmes données vivent dans deux volumes Docker nommés
(initialisés depuis l'image avec les droits de l'utilisateur applicatif, donc
sans `mkdir`/`chown` sur l'hôte) :

| Volume | Contenu | Montage |
|---|---|---|
| `hub_data` | `hub.sqlite`, `uploads/`, `.secret_key` | `/data` |
| `hub_certs` | générations de certificats, lien `active`, `fullchain.pem` (0644) et `privkey.pem` (0600), marqueur `.bootstrap`, état de rollback | `/certs` |

## Flux principaux

### Consultation (public)

1. Nginx reçoit la requête HTTPS, applique l'allowlist, proxy vers 13744.
2. Flask lit le catalogue (applications `enabled=1`) et rend la landing page —
   en **deux vues** (cartes et liste) issues du même jeu de données (voir plus
   bas).
3. Les cartes et les lignes de la liste pointent directement vers les URLs
   réelles des applications (nouvel onglet par défaut, réglage global dans
   `/admin/paramètres`).
4. Le Hub n'émet **aucune** requête vers ces URLs (pas de proxy, pas de SSRF).

### Gestion du catalogue (admin)

Session serveur (cookie `hub_session`, HttpOnly/Secure/SameSite=Strict, jeton
haché en base) + jeton CSRF par session + contrôle d'origine sur les POST +
verrouillage après échecs. CRUD complet, ordre (montée/descente), visibilité
immédiate, téléversement de screenshots (PNG/JPEG/WebP, 4 Mo, magic bytes).

### Remplacement du certificat (admin)

Deux méthodes d'import alimentent le **même** pipeline sécurisé :

```
PKCS#12 / PFX (.p12/.pfx [+ mot de passe])          PEM / CRT (avancé)
        ↓ app/certparse.py (mémoire seule)                  ↓ (PEM ou DER)
  feuille + clé + chaîne (racine omise)                 certificat + clé [+ chaîne]
        └──────────────────────┬─────────────────────────────┘
   helper.validate  → validation complète, métadonnées, ticket (10 min, usage unique)
   ↓ activation       → revalidation, sauvegarde de la paire active
   ↓ bascule atomique → nginx -t → reload → vérification du certificat servi
   ↓ succès            → ancienne génération purgée
   ↓ échec             → rollback : ancienne paire restaurée + reload
```

La lecture d'un bundle PKCS#12 se fait **dans l'application, en mémoire** : aucun
fichier temporaire, mot de passe éphémère jamais journalisé ni transmis au helper
(voir D13). Le helper ne voit que des PEM, comme avant.

### Remplacement du certificat en standalone (TLS direct)

1. L'administrateur importe le **PKCS#12** de la PKI (ou la paire PEM) : le
   bundle est lu **en mémoire** (`certparse.py`), la chaîne est extraite, la
   racine auto-signée est omise ; le mot de passe n'est jamais conservé.
2. La validation utilise `hub_certctl.validate_pair` — **les mêmes règles que le
   VPS** — puis la paire est déposée dans `hub_certs/staging/<ticket>` (0600,
   ticket à usage unique, 10 minutes).
3. L'activation écrit une génération, bascule le lien `active` (atomique), puis
   envoie **SIGHUP au maître gunicorn** : les workers sont redémarrés
   gracieusement et reconstruisent leur contexte SSL depuis les fichiers.
4. Le Hub **vérifie le certificat réellement présenté** (connexion TLS sur
   `127.0.0.1:8443` avec `SNI = HUB_TLS_HOSTNAME`, comparaison d'empreinte
   SHA-256) : c'est cette vérification — pas l'écriture sur disque — qui valide
   l'activation.
5. En cas d'échec : `restore` de la génération précédente, nouveau SIGHUP,
   revérification, et message explicite ; la suppression du marqueur
   `.bootstrap` marque le passage au certificat définitif.

### Renouvellement Let's Encrypt

Certbot (webroot `/var/www/hub-acme`, timer système sous verrou infra partagé)
puis hook de déploiement `/etc/letsencrypt/renewal-hooks/deploy/hub`, qui
rappelle le helper (`renew`) : même validation, même activation atomique, même
rollback que le parcours web — nginx ne lit jamais directement la lignée Certbot.

### Catégories et filtres publics

Les filtres de la landing page sont générés par les catégories comptant au moins
une **application affichée**, dans l'ordre administré. Une catégorie vide (ou
utilisée uniquement par des applications masquées) n'apparaît pas. Le filtre
passe par le slug (`/?category=fortinet`) ; la page fonctionne sans JavaScript
(liens GET), le filtrage instantané n'étant qu'une amélioration progressive.

### Thème clair / sombre

Un seul fichier CSS, deux jeux de valeurs de *tokens* (sombre = référence
visuelle, clair = second jeu). Le thème actif vient de `data-theme` sur `<html>`
(choix explicite de l'utilisateur, mémorisé en `localStorage`) ou, à défaut, de
`prefers-color-scheme` (première visite). `theme-init.js`, script externe chargé
dans `<head>` **avant** la feuille de styles, applique le choix mémorisé avant le
premier rendu : aucun flash, et la CSP reste stricte (`script-src 'self'`, aucun
script inline). La bascule est disponible sur le portail comme dans
l'administration, y compris sur la page de connexion.

### Vue du catalogue : cartes / liste

La landing rend **les deux vues en HTML serveur** à partir du même jeu de
données : une section `data-view-panel="cards"` (vue historique, captures
réelles) et une section `data-view-panel="list"` (rendu dense, **aucune
capture** — nom, catégorie, statut, description courte, CTA). Le CSS n'en
affiche qu'une selon l'attribut `data-catalog-view` posé sur `<html>` par
`catalog-view-init.js` avant le premier rendu, depuis `localStorage` (clé
`hub_catalog_view`) : `cards` par défaut, aucun clignotement au rechargement.

La bascule est une amélioration progressive : les deux boutons (`aria-pressed`)
sont révélés par `hub.js`, sans JavaScript la vue Cartes reste le comportement
par défaut. Recherche et filtres de catégories restent un **seul** moteur
(`hub.js`) qui marque les deux rendus via les mêmes attributs `data-*` ; seul le
décompte d'applications suit la vue affichée. La transition de vue est un léger
fondu, neutralisé par `prefers-reduced-motion`.

### Branding du header

Le libellé affiché à côté du logo SNS (« SNS | HUB ») vient de
`HUB_BRAND_LABEL` (`app/config.py`, défaut « HUB ») : trim, espaces normalisés,
caractères de contrôle retirés, 40 caractères au plus, échappement Jinja à
l'affichage — jamais de HTML. Valeur absente, vide ou invalide = libellé
générique. Purement visuel : la valeur n'entre dans aucune décision de routage,
de certificat, de stockage ou de session.

## Contraintes de sécurité

- Aucun secret dans Git ni dans l'image ; `runtime/` et `.env` sont ignorés.
- Clé privée : 0600 root, jamais renvoyée par la socket, jamais journalisée,
  jamais montée dans le conteneur applicatif.
- Le conteneur tourne en lecture seule (rootfs `read_only`), `cap_drop: ALL`,
  `no-new-privileges`, utilisateur non-root, seul `/data` et `/tmp` inscriptibles.
- En-têtes de sécurité applicatifs (CSP restrictive, X-Frame-Options,
  nosniff, Referrer-Policy, Permissions-Policy, HSTS derrière HTTPS).
- Frontière proxy explicite : `X-Forwarded-Proto`/`X-Forwarded-For` ne sont
  honorés que depuis le gateway du réseau Docker du projet.
- Validation stricte des URLs du catalogue (http/https uniquement, pas
  d'identifiants embarqués, pas de `javascript:`) ; aucune requête sortante.
- Branding : `HUB_BRAND_LABEL` est un texte simple, borné et échappé à
  l'affichage (aucun HTML arbitraire, aucun effet hors rendu).

## Ce que le Hub n'est pas

Pas d'orchestrateur, pas de proxy applicatif, pas de monitoring, pas de CMDB,
pas de gestion des comptes des autres applications, pas de microservices.

