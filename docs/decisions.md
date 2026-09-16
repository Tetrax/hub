# SNS Hub — Décisions structurantes

Chaque décision : Contexte / Décision / Pourquoi / Alternatives / Conséquences.
Seules les décisions structurantes sont documentées ici.

---

## D1 — Stack : Python 3.12 + Flask (rendu serveur) + JS léger + SQLite

**Contexte.** Le Hub est un catalogue/launcher : une landing page publique très
légère, une administration CRUD, et une gestion de certificat TLS. L'environnement
SNS comporte des applications Python (FortiUpgrade — qui porte aussi le mécanisme
autoritatif de certificats) et Node, sans obligation de cohérence de framework.

**Décision.** Backend Python 3.12 + Flask, templates Jinja2 rendus serveur,
JavaScript minimal sans framework (filtrage/recherche, confirmations, copie),
SQLite en fichier persistant. Dépendances runtime : `flask`, `gunicorn`.

**Pourquoi.** Le rendu serveur couvre entièrement le besoin ; il évite un SPA,
un bundler et une API séparée. Python permet de partager le même langage que le
mécanisme de certificats (openssl + stdlib) repris de FortiUpgrade. SQLite est
suffisant (un seul écrivain, volume minuscule) et se sauvegarde comme un fichier.

**Alternatives.** React/Vite + API REST : complexité (build, API, état) sans
bénéfice pour un catalogue. Node/Express : aucun avantage ici, et le code
certificat de référence est Python. PostgreSQL : inutile pour ce volume.

**Conséquences.** Landing page servie par le serveur (cache HTTP simple), admin
en formulaires HTML classiques avec CSRF ; toute évolution future (favoris, SSO)
reste possible sans refonte.

---

## D2 — Stockage : SQLite + uploads dans un répertoire runtime persistant

**Contexte.** Le Hub doit survivre aux restarts et recréations de conteneur :
applications du catalogue, screenshots, paramètres, sessions, compte admin.

**Décision.** Base SQLite dans `runtime/data/hub.sqlite` (WAL) ; screenshots dans
`runtime/data/uploads/` ; `runtime/` est un bind mount du conteneur, ignoré par
Git, sauvegardable par simple copie (`scripts/backup.sh`).

**Pourquoi.** Persistance indépendante du cycle de vie du conteneur, restauration
triviale, aucune dépendance à un serveur de base de données.

**Conséquences.** Le backup = base + uploads + (si gérés par le Hub) certificats.
Un fichier SQLite corrompu ne bloque pas le démarrage : il est détecté/refusé
proprement (voir `docs/operations.md`).

---

## D3 — Déploiement : Docker Compose depuis le dépôt canonique, pas de stack Portainer

**Contexte.** L'environnement mélange des stacks lancées en `docker compose` et
des stacks Portainer (`fortianonymous`). Le brief exige une source de vérité unique
et interdit toute copie de production divergente.

**Décision.** `compose.yaml` **versionné à la racine du dépôt** ; build du Dockerfile
avec contexte `.` ; déploiement par `docker compose` depuis
`/home/tetrax/workspace/hub`. Portainer reste un outil d'observation de
l'infrastructure ; aucune stack Portainer dupliquée (une stack Portainer créerait
un second Compose non versionné, en divergence avec le dépôt).

**Pourquoi.** Une seule source : le dépôt. `Git SHA → image → conteneur` reste
traçable (labels OCI + `HUB_GIT_SHA` affiché dans l'admin).

**Conséquences.** Le redéploiement se fait par script (`scripts/deploy.sh`) ;
les sauvegardes d'image précédente restent locales pour le rollback.

---

## D4 — Certificats : helper root + socket Unix + activation atomique (modèle FortiUpgrade)

**Contexte.** Le brief (sections 38-41, 92) exige une administration du certificat
TLS de Hub depuis `/admin` : lecture, upload, validation (clé/certificat/chaîne/
hostname), activation sûre (`nginx -t`, reload), rollback en cas d'échec, clés
privées jamais exposées. FortiUpgrade possède déjà un mécanisme éprouvé.

**Décision.** Reprendre les principes de FortiUpgrade, avec une implémentation
propre à Hub :

- générations immuables `.active-<hash>` + lien symbolique `active` (bascule
  atomique par `os.replace`), verrou inter-processus ;
- **helper privilégié root** (`helper/hub_cert_helper.py`, service systemd
  `hub-cert-helper.service` durci) exposé par socket Unix 0660 root:tetrax dans
  `/run/hub-cert-helper/` ; vérification `SO_PEERCRED` (uid/gid 1000) ;
- le conteneur applicatif ne peut ni écrire les fichiers du certificat ni
  remplacer le lien actif : il dialogue uniquement avec le helper ;
- workflow admin **Valider → Activer** : la validation renvoie les métadonnées et
  délivre un ticket à usage unique lié au contenu (10 min) ; l'activation
  revalide, sauvegarde l'ancienne paire, bascule, exécute `nginx -t`, recharge
  nginx, vérifie le certificat réellement servi en HTTPS (fingerprint SHA-256),
  et **rollback + reload** en cas d'échec ;
- renouvellement Let's Encrypt : webroot dédié `/var/www/hub-acme` + hook deploy
  certbot qui rappelle le helper (`renew`), sous le lock infra partagé.

**Pourquoi.** C'est le mécanisme le plus sûr et le plus éprouvé de l'environnement ;
réutiliser ses principes évite de réinventer une activation TLS risquée.

**Alternatives.** Copier le certificat via un volume inscriptible par l'application :
expose la clé privée en écriture au conteneur (refusé). Reprendre certctl.py de
FortiUpgrade tel quel : couplage FortiUpgrade (PFX, comptes admin embarqués)
inutile ici.

**Conséquences.** Un service host supplémentaire à maintenir (documenté, testé) ;
le rollback reste possible tant que l'ancienne génération est conservée.

---

## D5 — Authentification admin : compte unique, création au premier accès

**Contexte.** Le brief exige `/admin` protégé (compte, mot de passe hashé, session,
CSRF, anti-brute-force, logout, expiration) sans RBAC ni SSO, et **sans jamais
hardcoder de mot de passe**.

**Décision.** Un compte administrateur unique. Si aucun compte n'existe, `/admin`
affiche « Première configuration » et crée le compte (identifiant + mot de passe
12..1024 octets, choisi par l'administrateur — aucun mot de passe par défaut).
Hash scrypt (params encodés), sessions **serveur** persistées en SQLite (cookie
`HttpOnly`/`Secure`/`SameSite=Strict` portant un jeton aléatoire, seul le SHA-256
du jeton est stocké), CSRF par session, verrouillage progressif après échecs,
rotation du mot de passe depuis l'admin, CLI de secours `manage.py reset-admin`
(interactive, jamais de mot de passe en argument).

**Pourquoi.** Simple, robuste, auditable ; pas de secret initial à distribuer.

**Conséquences.** Pas de récupération par email en V1 (non demandée) ; le CLI
couvre le cas « mot de passe perdu ».

---

## D6 — Uploads de screenshots : validation stricte, stockage par identifiant

**Contexte.** Le brief (section 35) exige formats autorisés, limite de taille,
validation du vrai type, nom de fichier sécurisé, anti-path-traversal, stockage
persistant, remplacement/suppression, gestion des orphelins.

**Décision.** Upload limité à 4 Mo, PNG/JPEG/WebP vérifiés par **magic bytes**
(pas l'extension ni le `Content-Type` annoncé), nom de fichier généré
(`<uuid4>.<ext>`), suppression de l'ancien fichier au remplacement et à la
suppression de l'application, aucun traitement d'image lourd (pas de redimensionnement
serveur en V1).

**Conséquences.** Les images du catalogue sont servies telles quelles (contrôle de
charge raisonnable) ; un fichier orphelin résiduel est détecté par la commande
`manage.py report-orphans` (optionnelle, documentée).

---

## D7 — Screenshots initiaux : captures réelles des applications déployées

**Contexte.** Le brief exige de vrais screenshots, homogènes, sans données
sensibles, et interdit d'inventer des URLs.

**Décision.** Captures réelles des applications via un navigateur headless
(Chromium), viewport identique pour toutes les cartes, stockées dans
`runtime/data/uploads/`. Les applications du catalogue initial sont **uniquement**
celles réellement déployées sur le VPS et pertinentes pour les collaborateurs :

| Application | URL (source : config nginx réelle) |
|---|---|
| FortiUpgrade | https://fortiupgrade.valdev.me |
| FortiFlow | https://fortiflow.valdev.me |
| FortiFlow2 | https://fortiflow2.valdev.me |
| FortiAnonymous | https://fortianonymous.valdev.me |
| Vysion | https://vysion.valdev.me |

Exclus volontairement (documentés au rapport) : Scout (outil de veille en phase
de recherche), JOX (projet personnel non SNS), Portfolio (personnel/public),
Hermes (service technique d'agent), Portainer (infra).

**Conséquences.** Le catalogue initial reflète la réalité du VPS ; il s'administre
ensuite depuis `/admin`.

---

## D8 — Périmètre fonctionnel : launcher, pas proxy (et pas plus)

**Contexte.** Le brief liste explicitement ce que Hub ne doit pas devenir
(orchestrateur, proxy, monitoring, CMDB, ITSM…).

**Décision.** Aucune requête serveur vers les URLs du catalogue (pas de health
check, pas de SSRF) ; les URLs sont validées (http/https uniquement, pas de
`javascript:`, pas d'identifiants embarqués) et les liens s'ouvrent côté client.
L'état des applications est un simple champ `status` éditorial.

**Conséquences.** Pas de monitoring ni de disponibilité temps réel — volontaire.

---

## D9 — Loopback autorisé dans le vhost Hub (vérifiabilité locale)

**Contexte.** L'allowlist IP globale du VPS (`conf.d/00-application-access.conf`)
protège tous les domaines ; depuis le VPS lui-même, une requête vers
`https://hub.valdev.me` est donc refusée (403) — ce qui rend impossible toute
recette de production de bout en bout (TLS + vhost + application) depuis l'hôte,
alors que le brief exige une vérification réelle après déploiement.

**Décision.** Le vhost Hub évalue `allow 127.0.0.1; allow ::1;` **puis inclut le
fichier d'allowlist global** (`include /etc/nginx/conf.d/00-application-access.conf`).
La liste des IP autorisées reste définie dans un seul fichier (aucune copie,
aucune dérive) ; l'ouverture loopback n'expose rien de nouveau (un processus
local peut déjà joindre directement le port applicatif publié en loopback).

**Alternatives.** Recopier la liste dans le vhost : duplication et risque de
divergence à chaque changement d'IP. Ajouter une location de diagnostic : ne
teste pas le chemin réel. Ne rien faire : recette limitée à l'application,
sans preuve du chemin HTTPS réel.

**Conséquences.** Les vérifications d'exploitation sur le VPS empruntent le
chemin HTTPS réel ; le comportement 403 reste inchangé pour toute source non
autorisée.

---

## D10 — Screenshots servis en WebP

**Contexte.** Les captures réelles (1440×900) pèsent ~150–220 Ko en PNG ; les
cinq cartes de la landing représentaient ~870 Ko, l'essentiel du poids de page.

**Décision.** Les captures sont converties en WebP (qualité 82) avant
téléversement ; l'application accepte et sert PNG, JPEG et WebP indifféremment
(validation par magic bytes). Aucun traitement d'image côté serveur.

**Pourquoi.** ~70 % de poids en moins (358 Ko de page au total) sans perte
visible ; aucun coût serveur ni dépendance d'image en production.

**Conséquences.** Le catalogue stocke des `.webp` ; un PNG/JPEG reste accepté à
tout moment via l'admin.
