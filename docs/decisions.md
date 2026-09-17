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

---

## D11 — Catégories : entité en base, migration versionnée, repli protégé (V1.1)

**Contexte.** En V1, `apps.category` était un texte libre (avec suggestions) :
impossible de renommer une catégorie partout, de voir son usage, de la
supprimer proprement ou de contrôler l'ordre des filtres publics.

**Décision.** Table `categories` (nom, slug unique insensible à la casse,
position, `is_fallback`) et `apps.category_id` en clé étrangère `NOT NULL`.
Migration `user_version` 1 → 2, **transactionnelle et idempotente**, exécutée au
démarrage : elle crée les catégories à partir des textes existants (regroupés
sans tenir compte de la casse ni des espaces), garantit l'existence d'une
catégorie de repli et reconstruit la table `apps` sans perte d'identifiants,
d'images, de positions ni de visibilité.

La catégorie de repli « Autres » ne peut **ni être supprimée ni être renommée** :
elle est le point d'atterrissage de toute suppression de catégorie utilisée et
garantit qu'aucune application ne se retrouve sans catégorie. Supprimer une
catégorie utilisée exige une réassignation explicite (écran de confirmation qui
liste les applications concernées).

**Alternatives.** Garder le texte et « gérer » les catégories par convention :
aucune garantie d'intégrité, renommage partiel. Table de liaison N-N : complexité
inutile, une application n'a qu'une catégorie. Suppression avec `ON DELETE SET
NULL` : autoriserait des applications orphelines.

**Conséquences.** Les filtres publics sont générés par la base (une catégorie
vide, ou utilisée uniquement par des applications masquées, n'apparaît pas) ;
l'ordre des filtres suit l'ordre administré. Sauvegarde de la base effectuée
avant la migration de production ; le slug sert aux URLs (`/?category=fortinet`).

---

## D12 — Thème clair/sombre : tokens, choix explicite prioritaire, aucun flash (V1.1)

**Contexte.** La DA sombre est validée et ne doit pas être redessinée ; il faut
un mode clair réel (portail **et** administration), persistant, respectant la
préférence système à la première visite, sans flash au chargement.

**Décision.** Un seul jeu de *design tokens* sémantiques (`--bg-*`, `--panel*`,
`--border`, `--text`, `--muted*`, `--rose*`, états, médias, héros, logo) dont les
valeurs par défaut sont la palette sombre de référence. Le thème clair est un
second jeu de valeurs appliqué soit par `data-theme="light"` (choix explicite),
soit par `prefers-color-scheme: light` quand aucun choix n'existe. Aucun
composant ne code une couleur en dur, et la feuille n'est pas dupliquée.

Le choix est mémorisé en `localStorage` (aucun stockage serveur, donc aucun
cookie ni donnée personnelle), et appliqué par un script **externe** chargé dans
`<head>` avant la feuille de styles : pas de flash, et la CSP reste stricte
(`script-src 'self'`, aucun script inline). Un bouton discret dans l'en-tête
(soleil/lune, `aria-label` dynamique) bascule le thème sur le portail comme dans
l'administration ; il fonctionne dès la page de connexion.

**Alternatives.** Deux feuilles de styles (ou `@media` dupliqués) : maintenance
double. Script inline dans `<head>` : imposerait `'unsafe-inline'` ou un nonce
dans la CSP. Thème stocké côté serveur : complexité et données inutiles pour un
réglage purement visuel. `light-dark()` : élégant mais redondant avec des tokens
déjà explicites, et le repli multi-navigateurs aurait dupliqué les palettes.

**Conséquences.** Ajouter une couleur = ajouter un token (et sa valeur claire si
elle diffère) ; les deux blocs clairs doivent rester identiques (vérifié par un
test). Les captures d'écran des applications ne sont pas retouchées : seuls leurs
conteneurs et liserés s'adaptent au thème. `prefers-reduced-motion` reste
respecté.

---

## D13 — Import de certificats : PKCS#12/PFX lu par l'application, pipeline helper inchangé (V1.2)

**Contexte.** L'administrateur devait fournir certificat, clé et chaîne
séparément. Les autorités de certification délivrent très souvent un unique
bundle PKCS#12 (.p12/.pfx) protégé par mot de passe. Il fallait l'accepter sans
affaiblir le modèle de sécurité existant (helper root durci, socket vérifiée par
`SO_PEERCRED`, activation atomique, rollback).

**Décision.** L'application **extrait** le bundle en mémoire (`app/certparse.py`,
bibliothèque `cryptography` — aucun parseur PKCS#12 maison, aucun sous-process
OpenSSL, donc aucun mot de passe en ligne de commande), puis transmet la paire
PEM obtenue au helper **exactement comme aujourd'hui** : le protocole, les
contrôles `SO_PEERCRED` et le pipeline de validation/activation ne changent pas
d'un octet. Deux méthodes d'import cohabitent dans l'interface, PKCS#12 proposé
par défaut, sélecteur fonctionnel sans JavaScript.

Règles retenues :

- **certificat feuille** = celui qui correspond à la clé privée (jamais « le
  premier certificat ») ; **chaîne** reconstruite par relations émetteur/sujet,
  **racine auto-signée omise** (inutile en service, et c'est le helper qui
  valide la chaîne) ;
- **mot de passe** : secret éphémère, utilisé le temps de l'extraction
  (mémoire seule, aucun fichier temporaire), jamais journalisé, jamais stocké,
  jamais transmis au helper ; un mot de passe saisi pour un bundle non protégé
  ne bloque pas (nouvel essai sans mot de passe) ;
- **formats** : `.p12`/`.pfx` ; mode avancé PEM inchangé, complété par la
  détection **DER** (contenu réel, jamais l'extension) pour le certificat et la
  clé ;
- **limite dédiée** : 256 Ko par bundle (un PFX réel pèse quelques kilo-octets),
  et 16 certificats maximum dans un bundle.

**Hors périmètre (assumé).** PKCS#7 (.p7b/.p7c), Java KeyStore, magasins Windows
et conversions de formats rares : aucun bénéfice justifiant la complexité
supplémentaire (PKCS#12 couvre le cas réel, PEM/DER couvre le reste).

**Conséquences.** Un certificat importé (PKCS#12 ou PEM) reste actif jusqu'au
prochain renouvellement Let's Encrypt — informé dans l'interface et documenté
dans `docs/operations.md`. Le mode PEM existant n'est pas modifié
(non-régression testée), et l'interface indique clairement la méthode, la limite
de taille et le traitement du secret.

## D14 — Portabilité : Compose générique, surcharge VPS, configuration par variables (V1.3)

**Contexte.** SNS Hub était déployable, mais sa description d'infrastructure
(`compose.yaml`) portait cinq valeurs propres au VPS : port publié en loopback,
hostname `hub.valdev.me`, CIDR du proxy de confiance, source de bind du socket
helper et **sous-réseau Docker fixé `172.31.244.0/24`** (choisi uniquement pour
rendre déterministe l'adresse du gateway). Un audit de portabilité a conclu que
l'application elle-même était portable, mais que ces valeurs empêchaient un
`git clone` + `docker compose up -d` sur une VM générique — avec un risque de
conflit de sous-réseau en environnement d'entreprise.

**Décision.** Séparer **infrastructure** et **installation**, sans jamais
dupliquer le code applicatif ni introduire de notion de « mode » :

- `compose.yaml` devient **générique** : aucune valeur propre à une machine,
  tout par variables avec valeurs par défaut sûres (`HUB_BIND_IP=127.0.0.1`,
  `HUB_PORT=13744`, `HUB_UID/GID=1000`, `HUB_DATA_PATH=./runtime/data`,
  `HUB_TRUSTED_PROXY_CIDRS` vide, `HUB_TLS_HOSTNAME` vide) ; **plus aucun
  sous-réseau imposé** (Docker attribue le réseau automatiquement) ;
- `compose.vps.yaml` est une **vraie surcharge minimale** versionnée : sous-réseau
  fixé, CIDR du proxy local, hostname, socket helper, nom du conteneur. Compose
  fusionne/déduplique les entrées identiques (port, volume) ;
- `.env` (jamais versionné) porte la configuration d'installation ; `.env.example`
  documente les variables, sans secret ;
- `COMPOSE_FILE` (dans `.env`) sélectionne les fichiers Compose — **un seul**
  mécanisme de configuration, lu aussi par les scripts hôte (`backup.sh`,
  `prepare-data-dir.sh`) ;
- le code Python reste **strictement identique** dans les deux cas : aucune
  condition sur un « mode » (ni standalone, ni enterprise, ni behind-proxy).

**Alternatives rejetées.** Embarquer un reverse proxy (Caddy/Traefik/Nginx) dans
le stack : inutile puisque le scénario d'entreprise dominant est le TLS terminé
par l'infrastructure existante ; un système de profils nommés applicatifs :
c'est une différence de déploiement, pas de fonctionnalité ; deux fichiers
Compose complets : duplication et dérive garanties.

**Conséquences.** Le même commit se déploie sur le VPS
(`COMPOSE_FILE=compose.yaml:compose.vps.yaml`) et sur une VM Docker/Portainer
(`compose.yaml` seul). La configuration effective du VPS est **restée
identique** (comparaison des rendus `docker compose config` avant/après
migration) et la production n'a subi aucune régression. Un nouveau point
d'exploitation apparaît : le répertoire de données doit appartenir à
`HUB_UID:HUB_GID` (`scripts/prepare-data-dir.sh`, erreur explicite au démarrage
sinon).

## D15 — Helper certificat et Certbot optionnels (V1.3)

**Contexte.** Le helper savoir-faire fonctionnait déjà sans Nginx
(`HUB_CERT_RELOAD_NGINX=0` → activation sans `nginx -t`, sans reload, sans
vérification du certificat servi), mais deux contraintes d'**infrastructure**
l'interdisaient en pratique : l'unité systemd imposait `Requires=nginx.service`
(et `After=`), et `scripts/install-helper.sh` installait le hook Let's Encrypt
dans `/etc/letsencrypt/renewal-hooks/deploy/` — répertoire inexistant sans
Certbot, donc échec de l'installation (mode `set -e`).

**Décision.** Rendre les composants hôte réellement optionnels, sans relâcher le
durcissement :

- unité systemd : `Requires=nginx.service` supprimé, `After=` conservé
  (ordonnancement pur, sans exigence) ; chemins Nginx du sandbox systemd rendus
  optionnels (`-/run/nginx.pid`, `-/var/log/nginx`) ; **toutes** les protections
  conservées (root, `ProtectSystem=strict`, `NoNewPrivileges`,
  `RestrictAddressFamilies`, `CapabilityBoundingSet`, `MemoryDenyWriteExecute`,
  `RuntimeDirectory`…) ;
- `install-helper.sh` : détection de Certbot (`HUB_CERTBOT_HOOK_DIR`), message
  clair « Certbot non détecté — hook non installé » sans échec, avertissement si
  Nginx est absent (`HUB_CERT_RELOAD_NGINX=0` requis), échec explicite si
  systemd manque ;
- côté application : **rien à changer** — sans socket, `/admin/certificats`
  affiche « Gestion des certificats indisponible » (HTTP 200), refuse proprement les imports, et
  indique que le TLS est peut-être géré par l'infrastructure externe.

**Conséquences.** Trois profils d'exploitation cohérents, sans code applicatif
conditionnel : VPS (Nginx + helper + Certbot), VM avec helper sans Nginx
(`HUB_CERT_RELOAD_NGINX=0`), VM sans helper (TLS géré par un proxy). Sur le VPS,
le comportement observé est inchangé (`nginx -t`, reload, vérification du
certificat servi, rollback).

## D16 — Déploiement standalone : HTTPS direct dans le conteneur (V1.4)

**Contexte.** Les VM d'entreprise utilisent Portainer et n'ont ni Nginx, ni
Certbot, ni service systemd, ni accès SSH après le déploiement. Le modèle de
référence existe déjà dans SNS : **FortiUpgrade** déploie un unique conteneur
applicatif qui termine lui-même TLS (`ssl.SSLContext` + socket enveloppée),
stocke sa paire dans un volume et l'administre depuis son interface.

**Décision.** Reproduire ce modèle avec la serveur de Hub (gunicorn), sans proxy
supplémentaire :

- `compose.standalone.yaml` : **un seul service**, `hub_data` + `hub_certs` en
  volumes nommés, seul HTTPS publié (`${HUB_HTTPS_PORT:-443}` → `8443` interne),
  **une seule variable à saisir** (`HUB_HOSTNAME`) ;
- gunicorn sert HTTPS directement (`--certfile`/`--keyfile`, voir
  `app/gunicorn.conf.py`) sur des ports non privilégiés → ni `CAP_NET_BIND_SERVICE`,
  ni root, ni socket Docker ;
- **bootstrap** : l'entrypoint du conteneur (`app/standalone/entrypoint.sh`,
  transparent hors standalone) crée, avant le démarrage du serveur, un certificat
  **auto-signé** pour `HUB_HOSTNAME` (`app/certlocal.py`,
  `bootstrap_certificate`) marqué `.bootstrap` dans le volume. Il survit aux
  redémarrages, est annoncé comme **temporaire** dans l'interface et disparaît à
  la première activation réelle ;
- **rechargement** : l'activation écrit une nouvelle génération, bascule le lien
  `active`, envoie **SIGHUP au maître gunicorn** (rechargement gracieux : les
  workers reconstruisent leur contexte SSL depuis les fichiers) puis vérifie que
  le certificat **réellement présenté** (connexion TLS sur `127.0.0.1:8443`,
  `SNI = HUB_TLS_HOSTNAME`) correspond — sinon rollback complet. Mécanisme prouvé
  par prototype isolé : nouveau certificat servi, `RestartCount=0`, aucune requête
  en échec pendant le rechargement ;
- **HTTP/80** : non servi (compromis assumé : gunicorn n'écoute qu'un protocole
  par socket ; ajouter un second serveur pour la seule redirection violerait le
  principe « un seul serveur simple »). La procédure indique explicitement
  `https://FQDN`.

**Conséquences.** Aucune étape cachée après le déploiement : ni `ssh`, ni
`sudo`, ni `mkdir`/`chown` (les volumes nommés sont initialisés depuis l'image
avec les droits de l'utilisateur applicatif), ni `systemctl`, ni Certbot. Le VPS
et le mode « derrière un proxy » restent inchangés (même image, même
`compose.yaml`).

## D17 — Un backend certificat par mode de déploiement, une seule implémentation

**Contexte.** Trois environnements, trois façons de rendre un certificat
effectif : helper root + Nginx (VPS), proxy d'entreprise (aucune gestion côté
Hub), serveur HTTPS du conteneur (standalone).

**Décision.** Une seule abstraction (`app/certbackend.py`) choisie par
`HUB_CERT_BACKEND`, sans condition dispersée dans les vues :

- `helper` (défaut) — `app/certclient.py` → socket → `helper/hub_certctl.py` ;
- `local` — `app/certlocal.py` → même `hub_certctl` **dans le conteneur**
  (copié dans l'image, `openssl` installé) + SIGHUP + vérification du certificat
  servi ;
- `none` — gestion désactivée, TLS assuré en amont (page informative).

La validation, l'écriture des générations, la bascule atomique et le rollback
restent assurés par **`helper/hub_certctl.py`** : le standalone ne duplique ni
les règles de validation, ni les primitives d'activation.

## D18 — Réseau Docker externe et IPv4 statique : optionnels, tout par variables

**Contexte.** Certaines VM d'entreprise imposent un réseau Docker existant
(reverse proxy mutualisé, supervision) et parfois une adresse fixe attendue par
la règle de filtrage. Le standalone doit pouvoir s'y rattacher **sans figer
aucune valeur propre à un environnement** dans le dépôt.

**Décision.** Trois variables optionnelles dans `compose.standalone.yaml`,
saisies dans Portainer ; aucune n'est nécessaire au déploiement standard :

| Variable | Défaut | Effet |
|---|---|---|
| `HUB_DOCKER_NETWORK` | vide | réseau à rejoindre ; vide → réseau du stack (`<projet>_default`) |
| `HUB_DOCKER_NETWORK_EXTERNAL` | `false` | exige que ce réseau existe déjà (échec explicite sinon) |
| `HUB_IPV4_ADDRESS` | vide | IPv4 statique ; vide → adresse attribuée par Docker |

Mécanisme retenu, **vérifié en conditions réelles** (Compose rendu puis
démarrage effectif, les quatre combinaisons) :

- `ipv4_address: ${HUB_IPV4_ADDRESS:-}` : une valeur **vide est retirée du
  rendu** par Compose — la configuration reste valide et Docker attribue une
  adresse normalement (aucune valeur par défaut imposée) ;
- `name: ${HUB_DOCKER_NETWORK:-${COMPOSE_PROJECT_NAME:-hub-standalone}_default}`
  reproduit exactement le nom que Compose donnerait sans cette section : le
  déploiement standard est **inchangé**. Un `name` vide serait refusé
  (« invalid network name or ID: value is empty ») — d'où le défaut explicite ;
- `external: ${HUB_DOCKER_NETWORK_EXTERNAL:-false}` : garde-fou **optionnel**
  (`true`) qui refuse un réseau inexistant (`declared as external, but could
  not be found`) — sans lui, Compose **crée** un réseau homonyme et le Hub
  reste isolé du réseau attendu. Un booléen vide n'est pas acceptable
  (« invalid boolean ») : le défaut est donc explicite, jamais implicite ;
- le `down` **préserve** un réseau que Compose n'a pas créé ; volumes,
  certificat actif, healthcheck et chemin de dépôt Portainer restent inchangés.

**Compromis.** Trois variables plutôt qu'une : `HUB_DOCKER_NETWORK_EXTERNAL` ne
sert qu'à la vérification stricte (détection d'une faute de frappe) et peut
rester absente. L'IP statique doit appartenir à un sous-réseau du réseau cible
(message Docker explicite sinon) ; aucun sous-réseau n'est imposé par le dépôt.

## D19 — Branding du header configurable, purement visuel (`HUB_BRAND_LABEL`)

**Contexte.** Le header affiche « SNS | HUB » (logo + libellé). Une instance
d'entreprise doit pouvoir afficher un libellé différent (« SNS | MCO HUB ») sans
que le dépôt — désormais générique et déployable ailleurs — ne fige cette valeur
pour toutes les installations.

**Décision.** Une variable d'environnement `HUB_BRAND_LABEL`, lue par
`app/config.py` et exposée au gabarit (`base.html`) ; `HUB` par défaut, donc
aucune installation existante ne change. Validation volontairement simple :
trim, espaces internes normalisés, caractères de contrôle retirés, 40 caractères
au plus ; valeur absente, vide ou invalide → libellé générique ; échappement
Jinja à l'affichage (jamais de HTML — aucun `|safe`). Les fichiers Compose
exposent la variable en passthrough neutre (`${HUB_BRAND_LABEL:-}`) ; aucune
valeur d'instance n'est versionnée.

**Alternatives.** Libellé stocké en base et administrable : hors besoin (c'est
l'opérateur du déploiement qui personnalise une instance, pas l'utilisateur
quotidien) et cela ajouterait un écran et une migration. Système de branding
complet (logo, couleurs, thème par instance) : complexité sans besoin observé.
Valeur `MCO HUB` codée en dur : transformerait le dépôt générique en fork.
Validation « tout ou rien » (rejeter une valeur hors contraintes au lieu de la
normaliser) : un libellé est purement cosmétique, mieux vaut un rendu sûr et
prévisible qu'un échec de démarrage.

**Conséquences.** Aucune migration, aucun stockage : la variable n'affecte que
le rendu (hostname, certificat, base, sessions et URLs restent strictement
indépendants — un test le verrouille). La documentation (`.env.example`,
README, `docs/operations.md` §6/§9/§10.1) porte la variable ; les tests couvrent
défaut, trim, longueur, échappement et neutralité.

## D20 — Deux vues du catalogue : Cartes (défaut) et Liste dense

**Contexte.** La grille de cartes (capture, catégorie, statut, description, CTA)
devient très longue dès que le catalogue dépasse quelques dizaines
d'applications. Le besoin : un mode compact pour parcourir vite, sans captures,
dont la préférence suit l'utilisateur — sans réglage global ni impact admin.

**Décision.** La landing rend **les deux vues en HTML serveur** (même jeu de
données, mêmes attributs `data-*` de filtre) ; une section par vue
(`data-view-panel="cards"` / `"list"`) et un attribut `data-catalog-view` sur
`<html>` décident de ce qui est affiché. `catalog-view-init.js` applique la
préférence mémorisée (`localStorage`, clé `hub_catalog_view`) **avant le premier
rendu** ; sans choix, cartes. La bascule (boutons `aria-pressed`, révélés par
JS) est une amélioration progressive : sans JavaScript, la vue Cartes reste le
comportement historique. Recherche et filtre de catégories restent **un seul
moteur** (`hub.js`) sur les deux rendus ; seul le décompte suit la vue affichée.
La vue Liste n'affiche aucune capture ; badges, statuts et CTA sont ceux des
cartes (position du badge rendue contextuelle : posée sur le visuel en carte,
dans le flux en liste). Transition de vue en fondu léger, neutralisé par
`prefers-reduced-motion`.

**Alternatives.** Paramètre d'URL `?view=` rendu côté serveur : chaque bascule
rechargerait la page (ou exigerait un fetch) et la préférence devrait être
rejouée à chaque navigation — l'attribut local est plus simple. Transformation
JS des cartes en lignes : perd le rendu sans JavaScript et dépend de la
structure exacte des cartes. Second jeu de données JSON : deux sources de vérité
à maintenir pour le même catalogue. Réglage global dans `/admin` : la
préférence est par utilisateur, pas par instance.

**Compromis.** Le DOM double (les deux rendus coexistent, un seul affiché) —
acceptable pour un catalogue de quelques dizaines d'entrées, et c'est le prix
d'un rendu serveur complet sans JavaScript ; un seul jeu de données et un seul
moteur de filtre sont conservés. Aucun stockage serveur, aucune migration.

## D21 — Trivy en CI : contrôle informatif de l'image, jamais bloquant

**Contexte.** L'image Hub est construite depuis un `python:3.12-slim` épinglé par
digest, avec des dépendances Python épinglées, et le dépôt n'avait **aucune CI**
GitHub Actions. Le besoin : un contrôle de sécurité récurrent sur l'image
réellement produite (paquets OS + bibliothèques Python), dans la même philosophie
que FortiUpgrade — utile, actionnable, sans pipeline rouge permanent.

**Décision.** Un workflow unique (`.github/workflows/ci.yml`), deux jobs :
`tests` (suite pytest, bloquant) puis `security-scan` (**Trivy informatif**,
`needs: tests`) qui construit l'image réelle sans la pousser, la scanne
(`vuln-type: os,library`, `severity: HIGH,CRITICAL`, `ignore-unfixed: true`,
`exit-code: 0`) et publie le résumé d'étape, une annotation globale et l'artefact
`trivy-report` (JSON, 30 jours). Déclencheurs : `push` sur `main`,
`pull_request`, scan quotidien de `main` (05:23 UTC — volontairement distinct de
l'horaire FortiUpgrade) et `workflow_dispatch` pour un scan manuel. Le rendu du
rapport (`scripts/trivy_report.py`) est **tolérant par construction** : un
rapport absent ou illisible produit un avertissement explicite, jamais un
« aucune vulnérabilité » ni un échec. Trivy n'est installé nulle part dans le
produit (ni image, ni requirements, ni VPS, ni Portainer) et aucun secret n'est
nécessaire.

**Alternatives.** Trivy bloquant (`exit-code: 1`) : rejeté — une CVE de base
image ou une dépendance sans action possible produirait un pipeline rouge
permanent qui masque les vrais échecs ; les contrôles bloquants restent les tests
et la construction d'image. Scan à la demande uniquement : rejeté — une CVE
publiée entre deux commits ne serait pas vue ; le scan quotidien est précisément
là pour ça. Rapport JSON seul : rejeté — illisible dans l'interface ; le résumé
d'étape reprend compteurs, paquets, versions installées/corrigées et CVE.
Ingestion applicative des CVE (comme FortiUpgrade) : hors périmètre — le Hub n'a
ni alerting ni dashboard CVE et n'en a pas besoin aujourd'hui. Cache buildx
complet : rejeté — un cache simple `type=gha` suffit (le scan quotidien de main
inchangé réutilise les couches), sans mécanique fragile.

**Conséquences.** L'image peut porter des findings sans casser la CI : ils sont
visibles, datés, corrigeables (rafraîchir le digest de base ou mettre à jour un
paquet). Au 2026-09-17, le scan réel relève **13 vulnérabilités corrigibles
(3 CRITICAL, 10 HIGH), toutes dans des paquets OS Debian** de l'image de base
(`perl-base`, `gzip`, `libpcre2-8-0`, `libsqlite3-0`) — **0 côté Python** ; la
base du jour (`python:3.12-slim` au digest courant) porte encore ces versions :
aucune mise à jour « sûre et minimale » de l'image n'est donc disponible
aujourd'hui, le finding est documenté et sera résolu par un rafraîchissement du
digest quand Debian publiera les correctifs dans l'image officielle. Aucun impact
produit : version applicative inchangée, production non redéployée.

## D22 — Surveillance Trivy : Hub consomme la CI, il ne scanne jamais (V1.6)

**Contexte.** Le scan vit dans GitHub Actions (D21) et produit l'artefact
`trivy-report`. Personne ne lit ce rapport au quotidien : un changement (nouvelle
vulnérabilité, aggravation, disparition) doit être visible dans le Hub et signalé
par email **uniquement lorsqu'il se produit**. FortiUpgrade possède un dispositif
équivalent, mais dimensionné pour son moteur de notifications générique (outbox,
checkpoints, Microsoft 365) — le Hub n'en a pas besoin.

**Décision.**

- **Hub est un consumer** : il télécharge l'artefact du dernier run réussi
  (`Tetrax/hub`, workflow CI, branche `main`) — jamais de scan, jamais de Docker,
  jamais de `docker.sock`. Le téléchargement d'artefact exige un jeton même pour
  un dépôt public (vérifié le 2026-09-17 : liste publique, ZIP en 401) →
  `HUB_GITHUB_TOKEN` en **lecture seule** (fine-grained, portée `Actions: Read`),
  fourni par le déploiement, jamais en base, jamais rendu, jamais journalisé,
  envoyé uniquement vers `api.github.com` (retiré sur redirection inter-hôtes).
- **Validation stricte avant toute influence** : taille bornée, JSON, schéma,
  `ArtifactType = container_image`, contrat HIGH/CRITICAL corrigibles,
  identifiants bornés et filtrés, URLs `https` validées, nombre de findings borné ;
  un rapport invalide est refusé **en entier** — jamais d'ingestion partielle.
- **Identité d'un finding** : `CVE + paquet`, **sans** la version installée — une
  image reconstruite ne doit pas faire réapparaître les mêmes CVE comme nouvelles.
- **Publication atomique** : un échec de téléchargement, de validation ou de
  parse conserve intégralement le dernier état valide, qui vieillit visiblement
  (seuil 48 h, scan quotidien) ; jamais de fausse « résolution » quand GitHub est
  simplement indisponible. Un run ou un scan **plus ancien** que l'état courant est
  refusé : les SHA Git ne sont pas chronologiquement comparables, ce sont les
  horodatages du run et du scan qui tranchent.
- **Baseline silencieuse** : la première ingestion initialise l'état sans
  événement ni email (les findings déjà présents ne sont pas une alerte) ; l'admin
  affiche « Baseline initialisée — N CRITICAL / M HIGH ».
- **Delta** : apparition, disparition (« vulnérabilité non détectée dans la
  nouvelle image », jamais « corrigée » sans preuve) et changement de sévérité
  (aggravation ou atténuation). Un changement de version installée, de version
  corrigée ou de titre est un **rafraîchissement de contenu** : l'état est mis à
  jour, aucun événement, aucun email.
- **Un email au maximum par synchronisation**, et seulement si un événement
  notifiable existe : filtres par sévérité suivie et par type d'événement ; aucun
  email sans changement. Un échec SMTP **ne revient pas sur la baseline**
  (l'événement est marqué en échec, visible dans l'admin, renvoyable) — sinon la
  même CVE serait « nouvelle » à chaque synchronisation.
- **Planification sans second service** : un thread d'arrière-plan par worker
  gunicorn, un **verrou fichier inter-process** (`flock`) garantit qu'une seule
  synchronisation s'exécute à la fois ; cadence horaire (le scan CI est quotidien) ;
  robuste au redémarrage et au rechargement `SIGHUP` (certificat) ; le standalone
  reste **un seul conteneur** (aucun service `scheduler`, aucun
  Celery/Redis/RabbitMQ).
- **État dans la persistance existante** : `security_state` (ligne unique : dernier
  rapport, provenance, compteurs, erreurs) et `security_events` (historique
  minimal, statut de notification) dans `hub.sqlite` (schéma v3, tables
  additives) ; la configuration fonctionnelle vit dans la table `settings`.
- **Transport email : SMTP standard uniquement** (implicite TLS, STARTTLS ou sans
  chiffrement explicitement autorisé) — la primitive éprouvée de FortiUpgrade
  (smtplib, erreurs propres par étape, mot de passe jamais journalisé). Microsoft
  365 / Graph est documenté comme **évolution ultérieure** : l'intégrer
  doublerait le chantier email pour un besoin non démontré côté Hub. Le mot de
  passe vient de `HUB_SMTP_PASSWORD` (déploiement) ; il n'est ni stocké en base ni
  rendu au navigateur (l'interface n'affiche que « fourni / absent »).
- **Désactivation** : configuration fonctionnelle dans l'admin (une seule source
  de vérité), activable seulement si les credentials nécessaires sont fournis
  (jeton GitHub pour la synchronisation ; configuration SMTP complète pour les
  emails) ; surveillance et emails sont **deux commutateurs indépendants** ;
  **désactivée par défaut** — aucune instance n'est activée automatiquement.

**Alternatives.** Timer systemd hôte + `gh` (modèle FortiUpgrade) : rejeté — ne
fonctionne pas en standalone (ni hôte ni `gh`) et le bouton « Synchroniser
maintenant » exige que l'application elle-même sache télécharger. Second conteneur
`scheduler` : rejeté (D16, un conteneur). Celery/Redis : rejeté (dépendances sans
besoin). Jeton stocké en base : rejeté — secret d'infrastructure, il appartient au
déploiement. Ingestion d'un fichier déposé sur un volume par un script externe :
rejeté — le chemin actuel (artefact GitHub, un seul contrat CI→Hub) est celui
validé en D21. Microsoft Graph : reporté (voir ci-dessus).

**Conséquences.** La fonction est désactivée par défaut : le VPS et les instances
existantes gardent leur comportement actuel tant qu'un jeton n'est pas fourni et
la surveillance activée. Rien n'est publié hors de `/admin/security`. Le backup
existant couvre l'état et la configuration (même base). Réinitialiser une baseline
= supprimer la ligne `security_state` (procédure en `docs/operations.md` §16).

## D23 — Transport email administrable : SMTP ou Microsoft 365, secrets hors base (V1.6.1)

**Contexte.** La V1.6 (D22) livre les alertes email avec un SMTP minimal : les
paramètres non secrets se règlent dans l'admin, mais le mot de passe vient
obligatoirement du déploiement (`HUB_SMTP_PASSWORD`, variable Portainer) et
Microsoft 365 est reporté. Le besoin exprimé est le confort d'administration de
FortiUpgrade : ouvrir la webapp → choisir SMTP ou Microsoft 365 → saisir les
paramètres et le secret → tester l'envoi → les alertes utilisent cette
configuration, sans passage par Portainer. Cette décision **complète D22** et
remplace son point « Transport email : SMTP standard uniquement ».

**Décision.**

- **Un seul transport actif à la fois** : `security.email_transport`
  (`smtp` | `microsoft365`) persisté dans la table `settings` (SQLite) — même
  persistance que le reste (backup, restauration, aucune migration de schéma :
  la V1.6 → V1.6.1 est purement additive, les clés existantes sont conservées et
  les nouvelles ont des défauts sûrs). Les paramètres de l'autre transport
  **restent conservés** lors d'une bascule (retour arrière immédiat) mais ne sont
  jamais utilisés tant qu'il n'est pas sélectionné.
- **Secrets hors base** : mot de passe SMTP et secret client Microsoft 365 vivent
  dans des fichiers dédiés `$HUB_DATA_DIR/secrets/` (répertoire 0700, fichiers
  0600), écrits de façon **atomique** (fichier temporaire + `fsync` +
  `os.replace`, `O_NOFOLLOW`, refus des liens symboliques) par
  `app/mailsecrets.py`. Jamais en base, jamais dans une réponse HTTP (l'UI
  n'affiche qu'une **provenance**), jamais dans un log ou un traceback, jamais
  dans Git ou l'image. Champ vide = secret conservé ; remplacement et
  **suppression explicite** (contrôle dédié + confirmation + `confirm_delete`,
  CSRF) — jamais de suppression accidentelle.
- **Source de vérité sans ambiguïté** : le secret enregistré dans
  l'administration est **prioritaire dès qu'il existe** ; les variables
  d'environnement (`HUB_SMTP_PASSWORD`, `HUB_MICROSOFT_CLIENT_SECRET`) ne servent
  que de **bootstrap** tant qu'aucun secret administré n'existe, et l'UI affiche
  la provenance effective. Supprimer un secret administré ré-expose la valeur du
  déploiement (signalé à l'opérateur) ; aucun secret n'est jamais copié
  automatiquement d'une source vers l'autre.
- **SMTP** : serveur, port, sécurité (STARTTLS / TLS implicite / aucune),
  identifiant, expéditeur, **nom d'affichage** (en-tête `From`), destinataires
  (communs aux deux transports) et délai (5–60 s). La validation TLS reste
  active ; un relais à PKI interne exige d'injecter la CA de confiance dans
  l'image (documenté, pas de bouton « ignorer les erreurs TLS »).
- **Microsoft 365** : OAuth2 *client credentials* (`login.microsoftonline.com`)
  puis `POST https://graph.microsoft.com/v1.0/users/{mailbox}/sendMail` en JSON
  (`body.contentType` / `body.content`) — le modèle validé de FortiUpgrade, sans
  SDK. Endpoints **figés** (aucune saisie admin ne peut les remplacer), timeout
  partagé, erreurs traduites en messages opérateur avec classification AADSTS en
  **liste blanche** (tenant introuvable, secret refusé/expiré, Mail.Send
  manquante, boîte introuvable, limite, indisponibilité, timeout) ; ni secret, ni
  jeton, ni corps de réponse brut dans les messages ou les logs. Le `from` du
  message n'est **pas** imposé dans l'appel Graph (l'adresse affichée est celle
  de la boîte Exchange ; imposer un `from` différent expose à
  `ErrorSendAsDenied` — le modèle FortiUpgrade ne le fait pas).
- **Test d'envoi** : bouton dans `/admin/security` (section Alertes), utilisant
  **exactement** le transport sélectionné, la configuration persistée et le
  secret réel ; message de test dédié (« Test de configuration email »,
  transport, instance, date) sans aucune information sensible.
- **Moteur Trivy inchangé** : `send_delta_email` reste le point d'envoi unique et
  ne connaît que `EmailTransport` (SMTP ou Microsoft 365) ; transport incomplet →
  aucun envoi, événement marqué en échec, **baseline et delta intacts** (un échec
  ou une absence de transport ne rejoue jamais une alerte). Aucun email sans
  changement, un seul email par synchronisation.
- **SSRF** : l'hôte SMTP est une entrée administrateur assumée (relais interne
  d'entreprise) — protocole strict (nom d'hôte uniquement, ni schéma ni URL, ni
  espace), port borné 1–65535, aucune utilisation comme URL HTTP ; les endpoints
  Graph ne sont pas configurables. Rejet explicite d'un « URL générique ».
- **Backup** : `secrets/` est inclus dans `scripts/backup.sh` (archive 0600,
  comme la clé de session) et sa sensibilité est documentée ; la configuration
  non sensible vit déjà dans `hub.sqlite`.
- **Standalone** : aucun volume ni conteneur supplémentaire — les secrets vivent
  dans le volume `hub_data` existant ; **aucune variable email obligatoire**,
  une instance qui ne configure rien fonctionne normalement (page Alertes
  explicite : « transport incomplet »).
- **Sans redémarrage** : la configuration et les secrets sont relus à chaque
  envoi (pas de cache) — un changement prend effet immédiatement, sans restart
  ni redéploiement.

**Alternatives.** Secrets en base (même chiffrés) : rejeté — la clé de
chiffrement devrait vivre ailleurs de toute façon, pour un bénéfice nul.
Secrets uniquement par variables d'environnement : rejeté — c'est le point de
friction à supprimer (Portainer), et une variable survivante devient une seconde
source de vérité silencieuse. Volume secret supplémentaire (modèle
`/opt/fortios/*-secrets`) : rejeté — le répertoire de données est déjà persistant,
sauvegardé et initialisé par l'image ; un second volume compliquerait le
standalone sans rien protéger de plus. Chiffrement applicatif des secrets :
rejeté — la clé serait à côté du chiffré, complexité sans gain réel face à un
accès déjà restreint au conteneur (uid 1000). Multi-transport simultané,
carnet d'adresses, `from` Graph forcé, SDK Microsoft : rejetés — non demandés
(minimum sufficient change). `from` Graph : voir ci-dessus (risque
`ErrorSendAsDenied` démontré).

**Conséquences.** Le VPS peut passer à un transport configuré en webapp
(le mot de passe SMTP en variable continue de fonctionner en bootstrap) ; le
standalone devient entièrement configurable depuis Portainer *sans* variables
email. Les sauvegardes contiennent désormais des secrets email : elles restent en
0600 et doivent être protégées comme la clé de session. La restauration d'une
base V1.6 dans un Hub V1.6.1 est directe (clés additives) ; l'inverse exige de
revenir à l'image V1.6 **et** de ne pas compter sur les clés inconnues (elles
sont ignorées, aucun secret n'y transite).

## D24 — Jeton GitHub administrable : la surveillance s'active depuis la webapp (V1.6.2)

**Contexte.** D23 rendait administrables les secrets email, mais le jeton GitHub
de la surveillance restait un secret de déploiement (`HUB_GITHUB_TOKEN` dans
`.env` ou Portainer) : activer la surveillance exigeait encore un passage par le
déploiement, alors que le bouton et la configuration vivent déjà dans
`/admin/security`. Le besoin exprimé est la même chaîne que pour les autres
secrets : **secret administré prioritaire, sinon variable d'environnement, sinon
non configuré**.

**Décision.**

- Le jeton GitHub rejoint les secrets administrables de `app/secretstore.py`
  (module renommé depuis `app/mailsecrets.py`, sa portée couvrant désormais les
  secrets email **et** le jeton) : fichier `secrets/github-token` (répertoire
  0700, fichier 0600, écriture atomique, refus des liens), jamais en base,
  jamais rendu (provenance seulement), remplaçable (champ vide = conservé) et
  supprimable explicitement (confirmation + `confirm_delete` + CSRF).
- **Priorité** : jeton administré → `HUB_GITHUB_TOKEN` → non configuré. La
  synchronisation et la validation d'activation lisent le **jeton effectif**
  (`trivy_monitor.effective_github_token`) ; supprimer un jeton administré
  ré-expose la variable de déploiement (signalé à l'opérateur).
- **Portée inchangée** : le jeton reste un *fine-grained PAT* en **lecture
  seule** (`Actions: Read`) — c'est ce que le téléchargement d'artefact exige,
  même pour un dépôt public (vérifié en D22). L'administration ne fait que
  déplacer le stockage, pas les droits.
- L'activation de la surveillance devient **entièrement possible depuis la
  webapp** (jeton + transport email + commutateurs) ; aucune variable de
  déploiement n'est nécessaire pour l'usage normal.
- L'endpoint de suppression devient `/admin/security/secret/delete` (il ne
  concerne plus seulement les secrets email) ; la whitelist `SECRET_NAMES` est
  la seule autorité sur les noms acceptés.

**Alternatives.** Rester en variable d'environnement uniquement : rejeté — c'est
précisément la friction à supprimer (rotation = redéploiement). Jeton en base :
rejeté, comme en D23 (même raison : clé de chiffrement à côté du chiffré, aucun
gain face à un fichier 0600 déjà restreint au conteneur). GitHub App avec clé
privée + installation token : rejeté — plus sûr en théorie, mais un mécanisme de
plus à administrer pour un besoin non démontré. Permissions élargies : rejeté —
aucun besoin, la lecture seule suffit.

**Conséquences.** Rotation du jeton sans redéploiement ; la sauvegarde couvre le
jeton (archive 0600, même sensibilité que la clé de session) ; le standalone
s'active sans aucune variable. Le point de D22 « jeton stocké en base : rejeté »
reste vrai (rien en base) ; son point « secrets côté déploiement uniquement »
est remplacé par D23 (secrets email) et la présente décision (jeton GitHub).
