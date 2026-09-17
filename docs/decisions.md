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
