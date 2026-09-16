# SNS Hub — Architecture

## En une phrase

SNS Hub est un catalogue / launcher : une application web (Flask, rendu serveur)
qui liste les applications internes SNS et propose une administration
(catalogue, screenshots, certificat TLS). Il n'exécute, ne proxifie et ne
surveille aucune des applications qu'il référence.

## Vue d'ensemble

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

## Composants

### 1. Application (`app/`)

- **Flask 3.1** en rendu serveur (Jinja2), sans framework frontend ; CSS et JS
  faits main (un seul fichier CSS, un seul fichier JS de progressive enhancement).
- **gunicorn** (2 workers, 4 threads) sert l'application sur `0.0.0.0:8000`
  dans le conteneur ; le port n'est publié qu'en loopback (`127.0.0.1:13744`).
- **SQLite** (mode WAL) pour le catalogue, les sessions, le compte admin et les
  tentatives de connexion ; **uploads** de screenshots sur disque.
- Modules : `views_public.py` (landing, images, `/healthz`), `views_admin.py`
  (CRUD catalogue, paramètres, session), `views_cert.py` (parcours certificat),
  `certclient.py` + `hub_cert_protocol.py` (client du helper), `security.py`
  (en-têtes, frontière proxy, origine), `auth.py` (scrypt, sessions, CSRF,
  verrouillage), `uploads.py` (validation par magic bytes), `urls.py`
  (validation d'entrées), `manage.py` (CLI d'exploitation).

### 2. Helper certificat (`helper/`, root)

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

### 3. Nginx (hôte)

- Site dédié `hub.valdev.me` : port 80 (redirection + `/.well-known/acme-challenge`
  ouvert pour Let's Encrypt), port 443 (proxy inverse + TLS).
- Contrôle d'accès : l'allowlist IP globale
  (`/etc/nginx/conf.d/00-application-access.conf`) est incluse telle quelle dans
  le vhost ; le loopback est ajouté en premier pour permettre les vérifications
  d'exploitation sur le VPS (aucune duplication de la liste).
- `ssl_certificate` / `ssl_certificate_key` pointent sur
  `/var/lib/hub/certificates/active/{fullchain,privkey}.pem` (paire gérée).
- Copie versionnée de référence : `deploy/nginx/hub.valdev.me.conf`.

### 4. Données persistantes

| Donnée | Emplacement hôte | Conteneur | Sauvegarde |
|---|---|---|---|
| Catalogue, sessions, compte admin | `runtime/data/hub.sqlite` | `/data/hub.sqlite` | oui (copie SQLite cohérente) |
| Screenshots | `runtime/data/uploads/` | `/data/uploads/` | oui |
| Clé de signature des sessions | `runtime/data/.secret_key` (0600) | `/data/.secret_key` | oui (sensible) |
| Certificat + clé privée gérés | `/var/lib/hub/certificates/` (root) | non monté dans le conteneur | oui (archive séparée root) |

## Flux principaux

### Consultation (public)

1. Nginx reçoit la requête HTTPS, applique l'allowlist, proxy vers 13744.
2. Flask lit le catalogue (applications `enabled=1`) et rend la landing page.
3. Les cartes pointent directement vers les URLs réelles des applications
   (nouvel onglet par défaut, réglage global dans `/admin/paramètres`).
4. Le Hub n'émet **aucune** requête vers ces URLs (pas de proxy, pas de SSRF).

### Gestion du catalogue (admin)

Session serveur (cookie `hub_session`, HttpOnly/Secure/SameSite=Strict, jeton
haché en base) + jeton CSRF par session + contrôle d'origine sur les POST +
verrouillage après échecs. CRUD complet, ordre (montée/descente), visibilité
immédiate, téléversement de screenshots (PNG/JPEG/WebP, 4 Mo, magic bytes).

### Remplacement du certificat (admin)

```
upload (cert + clé [+ chaîne])
   ↓ helper.validate  → validation complète, métadonnées, ticket (10 min, usage unique)
   ↓ activation       → revalidation, sauvegarde de la paire active
   ↓ bascule atomique → nginx -t → reload → vérification du certificat servi
   ↓ succès            → ancienne génération purgée
   ↓ échec             → rollback : ancienne paire restaurée + reload
```

### Renouvellement Let's Encrypt

Certbot (webroot `/var/www/hub-acme`, timer système sous verrou infra partagé)
puis hook de déploiement `/etc/letsencrypt/renewal-hooks/deploy/hub`, qui
rappelle le helper (`renew`) : même validation, même activation atomique, même
rollback que le parcours web — nginx ne lit jamais directement la lignée Certbot.

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

## Ce que le Hub n'est pas

Pas d'orchestrateur, pas de proxy applicatif, pas de monitoring, pas de CMDB,
pas de gestion des comptes des autres applications, pas de microservices.
