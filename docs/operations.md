# SNS Hub — Exploitation

Toutes les commandes se lancent depuis le workspace canonique :

```bash
cd /home/tetrax/workspace/hub
```

## 0. Fichiers Compose et configuration

Le déploiement combine deux fichiers versionnés et un fichier local :

| Fichier | Rôle |
|---|---|
| `compose.yaml` | **générique et portable** (aucune valeur propre à une machine) |
| `compose.vps.yaml` | **surcharge du VPS de production** (sous-réseau fixé, proxy de confiance, hostname) |
| `compose.standalone.yaml` | **standalone Portainer** : HTTPS direct, un seul conteneur, volumes nommés (autonome, ne se combine pas) |
| `.env` | **configuration locale** (jamais versionnée) : port, bind IP, UID/GID, proxy de confiance, chemins |

`COMPOSE_FILE` (dans `.env`) indique quels fichiers Compose charger :

```bash
COMPOSE_FILE=compose.yaml                      # installation générique (défaut)
COMPOSE_FILE=compose.yaml:compose.vps.yaml     # VPS avec Nginx + helper locaux
# standalone : fichier unique, rien à combiner (voir §10)
```

Toutes les commandes `docker compose ...` du dépôt (scripts inclus) respectent
ce réglage. Vérifier le rendu effectif :

```bash
docker compose config | head -40
```

## 1. Déploiement et rollback

### Déployer le commit courant

```bash
./scripts/deploy.sh          # refuse un working tree sale ou un HEAD non poussé
```

Le script : vérifie Git → construit l'image taguée SHA (`scripts/build.sh`) →
`docker compose up -d --no-build` → attend le healthcheck → affiche image et
commit. Trace : `Git SHA → tag d'image → label OCI → conteneur`.

### Déployer une image précise (retour arrière)

```bash
HUB_IMAGE_TAG=<ancien SHA> HUB_GIT_SHA=<ancien SHA> docker compose up -d --no-build
```

L'image précédente est conservée sous `hub:previous` par `scripts/build.sh` ;
les images déployées restent présentes localement (le SHA est le tag).
Vérifier ensuite : `docker inspect hub-web --format '{{.Config.Image}} {{index .Config.Labels "org.opencontainers.image.revision"}}'`
puis `curl -k -o /dev/null -w '%{http_code}\n' https://127.0.0.1/ -H 'Host: hub.valdev.me'`.

### État et logs

```bash
docker compose ps
docker compose logs -f --tail 100 web
docker inspect -f 'health={{.State.Health.Status}} restarts={{.RestartCount}}' hub-web
curl -s http://127.0.0.1:13744/healthz
systemctl status hub-cert-helper --no-pager
journalctl -u hub-cert-helper -n 50 --no-pager
```

## 2. Compte administrateur

- **Première configuration** : ouvrir `https://hub.valdev.me/admin` depuis une
  IP autorisée ; tant qu'aucun compte n'existe, la page crée le compte (aucun
  mot de passe par défaut, minimum 12 octets).
- **Mot de passe perdu / rotation d'urgence** (interactif, jamais en argument) :

```bash
docker compose exec web python -m app.manage reset-admin
```

  Toutes les sessions actives sont invalidées par cette commande.
- **Changement courant** : `/admin/paramètres` (exige le mot de passe actuel).

## 3. Catalogue et screenshots

- Gestion complète dans `/admin/applications` (ajouter, modifier, masquer,
  réordonner, supprimer, remplacer le screenshot).
- Amorçage initial (idempotent, refuse si le catalogue contient déjà des
  applications) : `docker compose exec web python -m app.manage seed`.
- Fichiers non référencés : `docker compose exec web python -m app.manage report-orphans`.
- Captures des applications pour le catalogue (outil de poste de dev, Chromium) :

```bash
.venv/bin/python tests/browser/capture_apps.py --output /tmp/hub-shots
# puis téléversement : /admin/applications → modifier → screenshot
```

## 4. Catégories

- Gestion dans `/admin/categories` : créer, renommer (champ + « Renommer »),
  réordonner (↑/↓, ordre des filtres du portail), voir l'usage
  (« N applications »), supprimer.
- **Suppression** : une catégorie vide se supprime directement (confirmation).
  Une catégorie utilisée ouvre un écran de confirmation qui liste les
  applications concernées et exige une **réassignation** explicite (par défaut
  vers « Autres ») : aucune application ne peut se retrouver sans catégorie.
- **Catégorie de repli** (« Autres », `is_fallback = 1`) : non supprimable et non
  renommable — c'est le point d'atterrissage des réassignations.
- Depuis le formulaire d'une application, « + Nouvelle catégorie » crée la
  catégorie sans quitter la page (JavaScript requis ; sans JS, passer par
  `/admin/categories`).
- Sur le portail, n'apparaissent que les catégories comptant au moins une
  application affichée.

## 5. Migration de base de données

Le schéma est versionné (`PRAGMA user_version`) et migré **automatiquement** au
démarrage du conteneur (`db.init_db`) :

- migration `1 → 2` (V1.1) : `apps.category` (texte) → `categories` +
  `apps.category_id` (clé étrangère `NOT NULL`) ;
- transactionnelle (aucun état partiel), idempotente (relançable sans effet) et
  sans perte : identifiants, slugs, images, positions, visibilité et statuts des
  applications sont conservés ; les variantes de casse/espaces sont fusionnées.

En production, **prendre une sauvegarde avant** toute montée de version
(`sudo ./scripts/backup.sh`) : elle contient la base pré-migration. Pour rejouer
une migration sur une copie :

```bash
cp runtime/data/hub.sqlite /tmp/copie.sqlite
.venv/bin/python -c "from app import db; db.init_db('/tmp/copie.sqlite')"
.venv/bin/python -c "import sqlite3; c=sqlite3.connect('/tmp/copie.sqlite'); \
print(c.execute('PRAGMA user_version').fetchone()); print(c.execute('SELECT name FROM categories').fetchall())"
```

## 6. Thème clair / sombre

- Aucune exploitation : le choix est stocké par navigateur (`localStorage`),
  jamais côté serveur ; rien à purger ni à sauvegarder.
- Comportement : sans choix mémorisé, le thème suit `prefers-color-scheme` ;
  un clic sur la bascule fixe le choix pour ce navigateur.
- Vérification : `--bg-top` vaut `#0b0b0d` en sombre et `#f6f6f8` en clair
  (la recette navigateur contrôle les deux, la persistance et l'absence de
  flash).
- Ajouter une couleur = ajouter un token dans `app/static/css/hub.css` (valeur
  sombre par défaut, valeur claire dans les deux blocs clairs — ils doivent
  rester identiques, un test le vérifie).

### Vue du catalogue : Cartes / Liste

- Cartes = comportement historique, vue par défaut ; Liste = rendu dense sans
  capture, bascule dans la barre de résultats, préférence mémorisée par
  navigateur (`localStorage`, clé `hub_catalog_view`) — aucun réglage serveur,
  rien à purger ni à sauvegarder. Sans JavaScript, la vue Cartes s'applique.
- Ajouter une information à la vue Liste = la poser dans les **deux rendus**
  (`app/templates/index.html`, sections `data-view-panel="cards"` et
  `"list"`) avec les mêmes attributs `data-*` : le moteur de filtre et le
  décompte de la landing sont uniques.

### Branding du header

- Libellé configurable par `HUB_BRAND_LABEL` (« HUB » par défaut), purement
  visuel : aucun effet sur le hostname, le certificat, la base, les sessions ou
  les URLs. Texte simple (espaces normalisés, 40 caractères au plus, échappé) ;
  valeur vide ou invalide = libellé générique.
- Modifier le libellé d'une installation = changer la variable puis redéployer
  (`docker compose up -d` suffit) ; le VPS de production peut rester sans la
  variable.

## 7. Certificat TLS

### Importer un certificat (deux méthodes)

`/admin/certificats` → « Importer un certificat » :

- **PKCS#12 / PFX (recommandé)** : un seul fichier `.p12`/`.pfx`, avec son mot de
  passe s'il est protégé (laisser vide sinon — un mot de passe saisi pour un
  bundle non protégé n'empêche pas l'import). Limite : 256 Ko.
  L'application extrait le certificat feuille (celui qui correspond à la clé
  privée), la clé et la chaîne (racine auto-signée omise), **en mémoire** : le
  mot de passe n'est ni journalisé, ni stocké, ni transmis au helper.
- **PEM / CRT avancé** : certificat (PEM ou DER), clé privée non chiffrée (PEM ou
  DER) et chaîne PEM optionnelle — comportement d'origine inchangé.

Dans les deux cas : validation complète (mêmes règles partout) → résumé affiché
(sujet, émetteur, SAN, dates, empreinte, méthode, taille de chaîne) →
**activation explicite** → bascule atomique, rechargement du serveur,
vérification du certificat réellement servi, rollback automatique en cas
d'échec.

Selon le déploiement, la validation et le rechargement sont assurés par le
**helper root** (VPS : `nginx -t`, reload Nginx) ou par le **serveur HTTPS du
conteneur** (standalone : `SIGHUP` à gunicorn, aucune intervention sur l'hôte).

> Un certificat importé manuellement reste actif **jusqu'au prochain
> renouvellement Let's Encrypt** : le timer Certbot (~30 jours avant l'expiration
> du certificat Let's Encrypt) rappelle le hook de déploiement, qui réinstalle la
> paire Let's Encrypt. Pour conserver durablement un certificat importé, il faut
> désactiver le renouvellement pour ce domaine (`sudo certbot renew --cert-name
> hub.valdev.me ...` ou le timer) — décision d'exploitation, non automatisée ici.

### Déploiement standalone : certificat temporaire puis certificat définitif

Au premier démarrage d'un déploiement `compose.standalone.yaml`, **aucun
certificat n'existe** : le conteneur génère automatiquement un certificat
**auto-signé** pour `HUB_HOSTNAME` (volume `hub_certs`, marqueur `.bootstrap`),
ce qui rend le Hub immédiatement joignable en HTTPS — le navigateur affiche un
avertissement tant que le certificat définitif n'est pas installé. Cet état est
annoncé dans `/admin/certificats` (« Certificat temporaire de bootstrap »).

Procédure complète, **sans SSH** :

1. ouvrir `https://<HUB_HOSTNAME>` (accepter l'avertissement du certificat
   temporaire) ;
2. créer le compte administrateur (`/admin/setup`) ;
3. **Administration → Certificats** → sélectionner le **PKCS#12** fourni par la
   PKI, saisir son mot de passe → *Valider* ;
4. vérifier le résumé affiché (sujet, SAN = `HUB_HOSTNAME`, dates, chaîne) puis
   *Activer ce certificat*.

Le serveur est rechargé (SIGHUP) et le certificat **réellement présenté** est
vérifié : l'interface confirme que le certificat servi correspond à la paire
gérée. En cas d'échec, la paire précédente est restaurée automatiquement et un
message explicite est affiché — le Hub reste joignable en HTTPS. Le certificat
définitif remplace alors le certificat temporaire, qui n'est plus utilisé.

Un certificat **périmé** de bootstrap est régénéré au démarrage suivant ; un
certificat définitif n'est jamais touché.

### Consulter / remplacer

`/admin/certificats` : état de la paire active (sujet, émetteur, SAN, dates,
jours restants, empreinte, correspondance avec le certificat servi par Nginx)
et remplacement en deux temps (valider → activer).

### Vérifications en ligne de commande

```bash
sudo sh -c 'set -a; . /etc/hub-cert-helper.env; set +a; python3 /opt/hub-cert-helper/scripts/hub_cert_helper.py status'
sudo ls -la /var/lib/hub/certificates/ /var/lib/hub/certificates/active/
openssl s_client -connect 127.0.0.1:443 -servername hub.valdev.me </dev/null 2>/dev/null | openssl x509 -noout -subject -dates -fingerprint -sha256
```

### Amorçage manuel (nouvelle machine / reconstruction)

1. `sudo scripts/install-helper.sh` (installe `/opt`, le service, l'env, et le hook
   Certbot **si Certbot est présent**) ;
2. obtenir la paire (certbot webroot ou PKI interne) ;
3. `sudo sh -c 'set -a; . /etc/hub-cert-helper.env; set +a; python3 /opt/hub-cert-helper/scripts/hub_cert_helper.py install --cert <fullchain.pem> --key <privkey.pem>'`
   → validation, activation, `nginx -t`, reload, vérification du certificat servi.

### Sans helper (VM sans Nginx, TLS géré ailleurs)

Le helper est **optionnel** : sans lui, la page `/admin/certificats` affiche
« Gestion des certificats indisponible » et refuse proprement les imports ; tout le reste du Hub
fonctionne. Rien à configurer — ne pas installer le helper suffit.

### Helper sans Nginx

`HUB_CERT_RELOAD_NGINX=0` dans `/etc/hub-cert-helper.env` rend le helper
autonome de Nginx : il valide et active la paire (bascule atomique + rollback)
sans exécuter `nginx -t`, sans recharger Nginx et sans vérifier le certificat
servi (cette vérification suppose un port 443 local). Utile si le TLS est
terminé par un équipement externe qui lit la paire déposée dans
`/var/lib/hub/certificates/active/`.

```bash
sudo sed -i 's/^HUB_CERT_RELOAD_NGINX=1/HUB_CERT_RELOAD_NGINX=0/' /etc/hub-cert-helper.env
sudo systemctl restart hub-cert-helper
sudo systemctl status hub-cert-helper --no-pager
```

### Mise à jour du helper

```bash
sudo scripts/install-helper.sh        # unité + env + hook (Certbot optionnel)
sudo systemctl restart hub-cert-helper
docker compose exec web ls -l /run/hub-cert-helper/   # le conteneur doit voir la socket
```

L'unité conserve le répertoire de socket entre deux redémarrages
(`RuntimeDirectoryPreserve=yes`) : un simple redémarrage du helper n'invalide
donc plus le montage du conteneur. Si le répertoire a été **recréé** (redémarrage
de l'hôte, ou `/run` nettoyé), recréer le conteneur :
`docker compose up -d --force-recreate --no-build web`.

### Renouvellement Let's Encrypt

Automatique (`certbot.timer` + hook `/etc/letsencrypt/renewal-hooks/deploy/hub`).
Contrôles utiles :

```bash
sudo certbot renew --cert-name hub.valdev.me --dry-run
sudo ls -la /var/www/hub-acme/.well-known/acme-challenge/   # vide au repos
```

Le renouvellement réel se déclenche ~30 jours avant l'expiration ; il
re-valide la paire et recharge Nginx via le helper (jamais d'écriture directe
dans `active/`).

## 8. Sauvegarde et restauration

```bash
sudo ./scripts/backup.sh                 # destination : HUB_BACKUP_DIR
HUB_BACKUP_DIR=/chemin sudo ./scripts/backup.sh
```

La destination est résolue dans cet ordre : `HUB_BACKUP_DIR` (environnement),
puis `HUB_BACKUP_DIR` du fichier `.env`, puis `./backups/hub` (défaut portable).
Le VPS de production utilise `/home/tetrax/backups/hub` (valeur de son `.env`).
Nombre d'archives conservées : `HUB_BACKUP_KEEP` (défaut 10).

Contenu : `hub.sqlite` (copie cohérente), `uploads/`, `secret_key`,
`MANIFEST.txt`, plus une archive séparée des certificats (`hub-certificates-*.tar.gz`).

### Restauration

Les données vivent dans le répertoire pointé par `HUB_DATA_PATH`
(`./runtime/data` par défaut). Restauration complète :

```bash
ARCHIVE=/chemin/hub-backup-<stamp>.tar.gz
sudo tar -xzf "$ARCHIVE" -C /tmp/hub-restore
sudo scripts/prepare-data-dir.sh              # crée runtime/data au bon UID/GID
sudo install -o "$(stat -c %u runtime/data)" -g "$(stat -c %g runtime/data)" \
     -m 0644 /tmp/hub-restore/hub.sqlite runtime/data/hub.sqlite
sudo cp -a /tmp/hub-restore/uploads/. runtime/data/uploads/
sudo install -m 0600 -o "$(stat -c %u runtime/data)" -g "$(stat -c %g runtime/data)" \
     /tmp/hub-restore/secret_key runtime/data/.secret_key
sudo chown -R "$(stat -c %u runtime/data):$(stat -c %g runtime/data)" runtime/data
docker compose up -d --no-build && curl -s http://127.0.0.1:13744/healthz
```

Restauration partielle : seule la base (`hub.sqlite`) ou seuls les `uploads/`
peuvent être remis en place de la même façon ; la clé de session
(`.secret_key`) n'est utile que pour conserver les sessions en cours.

Certificats : restaurer `hub-certificates-*.tar.gz` dans `/var/lib/hub/`
(le lien `active` est inclus) puis `sudo nginx -t && sudo systemctl reload nginx`
(sous le verrou infra si d'autres changements nginx sont en cours). Sans
déploiement local de certificats, cette archive n'existe pas.

## 9. Installation sur une nouvelle VM

Scénario cible : Linux + Docker + Docker Compose (+ Portainer en option),
**sans Nginx local, sans Certbot, sans helper**. Le Hub fonctionne intégralement
(landing, admin, catégories, recherche, thèmes, CRUD, uploads, SQLite, sessions,
healthcheck, sauvegarde) ; seule la gestion des certificats est indisponible
(elle suppose un Nginx local).

```bash
git clone https://github.com/Tetrax/hub && cd hub
cp .env.example .env                    # ajuster HUB_BIND_IP, HUB_PORT, HUB_UID/GID…
sudo scripts/prepare-data-dir.sh        # crée runtime/data au bon propriétaire
docker compose up -d --build            # ou HUB_IMAGE_TAG=<sha> … --no-build
docker compose ps                       # attendre « healthy »
curl -s http://127.0.0.1:13744/healthz  # {"status":"ok","version":"1.5.0",…}
```

Ensuite :

- **accès direct** : `HUB_BIND_IP=0.0.0.0` (ou l'IP LAN) dans `.env`, port ouvert
  uniquement au réseau autorisé (pare-feu / ACL) — le Hub n'a pas d'allowlist IP
  propre, son contrôle d'accès est le compte admin ;
- **derrière un proxy** : voir §11 ;
- **certificat TLS** : géré par l'infrastructure porteuse (§11) ou, si le Hub
  doit gérer lui-même la paire, en installant le helper (§7) ;
- **HTTPS avec Nginx local** : exemple générique
  `deploy/nginx/hub-generic.conf.example` (placeholders `HOSTNAME`, `UPSTREAM`,
  `CERT_PATH`, `KEY_PATH`) ; sur RHEL/Rocky/Alma, l'y déposer dans
  `/etc/nginx/conf.d/` ;
- **sauvegarde** : `sudo ./scripts/backup.sh` (§8), à planifier (timer systemd
  ou cron) — non automatisé par défaut ;
- **branding** (optionnel) : `HUB_BRAND_LABEL=<libellé>` dans `.env` pour
  personnaliser le header de cette installation (voir §6).

### VPS de production (reproduction à l'identique)

1. Cloner `https://github.com/Tetrax/hub` dans `/home/tetrax/workspace/hub` ;
2. `cp .env.example .env` puis renseigner `HUB_BACKUP_DIR=/home/tetrax/backups/hub`
   et `COMPOSE_FILE=compose.yaml:compose.vps.yaml` ;
3. `sudo scripts/prepare-data-dir.sh` ;
4. `sudo scripts/install-helper.sh` ;
5. config Nginx `deploy/nginx/hub.valdev.me.conf` → `sites-available` + symlink →
   `sudo nginx -t && sudo systemctl reload nginx` ;
6. certificat : certbot (`--webroot -w /var/www/hub-acme -d hub.valdev.me`) puis
   amorçage helper (§7) ;
7. `./scripts/deploy.sh` ou `HUB_IMAGE_TAG=<sha> docker compose up -d --no-build` ;
8. restaurer la sauvegarde (§8) si nécessaire.

## 10. Déploiement depuis Portainer

### 10.1 Standalone : HTTPS direct, un seul conteneur (recommandé en VM d'entreprise)

Aucun prérequis sur la machine au-delà de Docker + Portainer, aucun accès SSH :

| Champ Portainer | Valeur |
|---|---|
| Repository URL | `https://github.com/Tetrax/hub` |
| Repository reference | `refs/heads/main` |
| Compose path | `compose.standalone.yaml` |
| Environment variables | `HUB_HOSTNAME=hub.sns-security.lan` (obligatoire) · `HUB_HTTPS_PORT=443` (optionnel) · `HUB_BRAND_LABEL=<libellé>` (optionnel, purement visuel) · `HUB_DOCKER_NETWORK` / `HUB_IPV4_ADDRESS` (optionnels, voir ci-dessous) |

Puis *Deploy the stack* → attendre `healthy` → ouvrir
`https://hub.sns-security.lan` → créer le compte administrateur → installer le
PKCS#12 de la PKI (§7). C'est tout : ni `ssh`, ni `sudo`, ni `mkdir`/`chown`, ni
`systemctl`, ni Nginx, ni Certbot, ni socket Docker. Les volumes `hub_data` et
`hub_certs` sont créés et initialisés automatiquement.

Détails utiles :

- seul **HTTPS (443)** est publié ; HTTP/80 n'est pas servi (choix assumé : un
  serveur unique pour le TLS, voir D16) — indiquer explicitement `https://` ;
- le port interne (8443) n'est pas privilégié : le conteneur reste **non-root**
  avec `cap_drop: ALL` et `no-new-privileges` ;
- mise à jour d'image : redéployer la stack (ou changer `HUB_IMAGE_TAG`) ; les
  volumes et le certificat actif sont conservés.

#### Rattacher Hub à un réseau Docker existant (optionnel)

Utile pour rejoindre un réseau d'entreprise (reverse proxy mutualisé, supervision,
annuaire). Tout se fait par variables, dans Portainer — rien n'est figé dans le
dépôt, et le déploiement standard reste inchangé si rien n'est saisi :

| Variable | Effet |
|---|---|
| `HUB_DOCKER_NETWORK=<nom>` | Hub rejoint ce réseau Docker au lieu du réseau du stack. Vide (défaut) : réseau `<nom du stack>_default`, créé par Compose. |
| `HUB_DOCKER_NETWORK_EXTERNAL=true` | Exige que ce réseau **existe déjà** (sinon le déploiement échoue explicitement). Recommandé dès qu'on nomme un réseau d'entreprise. |
| `HUB_IPV4_ADDRESS=<adresse>` | IPv4 **statique** de Hub sur ce réseau. Vide (défaut) : Docker attribue une adresse normalement. |

```yaml
# Exemple : Network → Environment variables
HUB_HOSTNAME=hub.sns-security.lan
HUB_DOCKER_NETWORK=reseau-applicatif
HUB_DOCKER_NETWORK_EXTERNAL=true
HUB_IPV4_ADDRESS=172.30.250.12
```

Points vérifiés par la recette (`tests/vm/standalone-check.sh`) :

- **réseau attribué par Docker** quand `HUB_IPV4_ADDRESS` est vide — les trois
  variables peuvent être laissées vides sans invalider la configuration ;
- **IP statique réellement portée** par le conteneur quand elle est fournie ;
- **`down` préserve un réseau existant** : Compose ne supprime que les réseaux
  qu'il a lui-même créés ;
- l'IP statique doit appartenir à un **sous-réseau du réseau cible** — sinon
  Docker refuse au démarrage (`no configured subnet contains IP address …`) ;
- un nom de réseau inexistant avec `HUB_DOCKER_NETWORK_EXTERNAL=true` échoue
  explicitement (`declared as external, but could not be found`) ; sans ce
  garde-fou, Compose créerait un réseau homonyme et Hub resterait isolé ;
- si un reverse proxy se trouve sur le réseau rejoint, `HUB_TRUSTED_PROXY_CIDRS`
  peut être renseigné en complément (facultatif : Hub termine TLS lui-même) ;
- le redéploiement ne change rien aux **volumes**, au **certificat actif**, au
  **healthcheck** ni au chemin de dépôt Portainer.

### 10.2 Variante générique (Nginx/proxy sur l'hôte, ou VM gérée en SSH)

Le même `compose.yaml` versionné est utilisé — aucune stack spécifique n'est
créée dans Portainer.

1. **Préparer l'hôte** (hors Portainer, en SSH) : cloner le dépôt dans le
   répertoire de travail voulu, `cp .env.example .env`, ajuster les valeurs, puis
   `sudo scripts/prepare-data-dir.sh` (le répertoire de données doit appartenir à
   `HUB_UID:HUB_GID`, sinon le conteneur ne peut pas écrire) ;
2. **Stack** → *Add stack* → *Repository* → URL
   `https://github.com/Tetrax/hub`, branche `main`, **Compose path**
   `compose.yaml` (ajouter `compose.vps.yaml` uniquement sur le VPS) ;
3. **Variables d'environnement** : saisir celles de `.env` (`HUB_BIND_IP`,
   `HUB_PORT`, `HUB_UID`, `HUB_GID`, `HUB_TRUSTED_PROXY_CIDRS`, `HUB_DATA_PATH`,
   `HUB_IMAGE_TAG`…) — Portainer les injecte comme le ferait `.env` ;
4. **Déployer** : Portainer construit l'image (contexte = clone du dépôt) si
   `--build` est actif, sinon fournir une image déjà construite via
   `HUB_IMAGE_TAG` + `docker load` (§12) ;
5. **Vérifier** : `docker compose ps` (ou l'UI) → *healthy*, puis
   `curl http://<hôte>:<port>/healthz` ;
6. **Accès** : port publié selon `HUB_BIND_IP`/`HUB_PORT` ; derrière un reverse
   proxy, voir §11.

Le helper certificat (et le vhost Nginx) restent **hors** Portainer : ce sont des
composants de l'hôte, installés une fois en SSH (`scripts/install-helper.sh`).

## 11. Derrière un reverse proxy externe (mode recommandé en entreprise)

```
Utilisateur ── HTTPS ──▶ F5 / HAProxy / Nginx / LB d'entreprise ── HTTP ──▶ Hub (conteneur)
```

Côté Hub (`.env`) :

```bash
HUB_BIND_IP=127.0.0.1            # ou l'IP LAN si le proxy est sur une autre machine
HUB_TRUSTED_PROXY_CIDRS=10.20.30.5/32   # IP SOURCE du proxy (pas celle des clients)
HUB_TLS_HOSTNAME=hub.intra.example      # affichage seulement
# pas de helper, pas de Certbot : le certificat vit sur l'équipement
```

Le proxy doit transmettre au minimum : `Host`, `X-Forwarded-Proto` et
`X-Forwarded-For` (voir `deploy/nginx/hub-generic.conf.example`).

**Pourquoi `HUB_TRUSTED_PROXY_CIDRS` est indispensable** : le Hub n'accepte
`X-Forwarded-Proto`/`-For` que si la connexion vient d'un CIDR déclaré. Sans
cette valeur (ou depuis une autre source), les en-têtes sont ignorés :
détection HTTPS impossible (donc cookie de session **sans** `Secure` et pas de
HSTS), et l'IP journalisée serait celle du proxy. Les en-têtes d'un client
quelconque ne peuvent donc jamais forger une origine ou un schéma.

Dans ce mode : **le certificat n'est jamais géré par le Hub** — il est installé
et renouvelé sur le proxy / load balancer. La page `/admin/certificats` signale
simplement que le helper est indisponible, ce qui est attendu.

## 12. Environnement sans Internet (offline)

Le **fonctionnement** du Hub n'exige aucun accès Internet (aucune ressource
externe, aucune police distante, aucun appel sortant). Seule l'**installation**
en a besoin (image de base + `pip`). Sur une machine connectée :

```bash
scripts/build.sh <tag>            # construit hub:<tag>
scripts/save-image.sh <tag>       # → hub-<tag>.tar.gz (quelques centaines de Mo)
```

Sur la VM isolée :

```bash
git clone <dépôt> && cd hub && cp .env.example .env
scripts/load-image.sh hub-<tag>.tar.gz
echo 'HUB_IMAGE_TAG=<tag>' >> .env
sudo scripts/prepare-data-dir.sh
docker compose up -d --no-build
```

Le renouvellement Let's Encrypt, lui, suppose un accès réseau à l'ACME ; sur un
réseau isolé, utiliser des certificats fournis par la PKI interne (import
manuel, ou certificat géré par le proxy).

## 13. Dépannage

| Symptôme | Piste |
|---|---|
| `hub-web` unhealthy, journal « Répertoire de données non inscriptible » | le répertoire de `HUB_DATA_PATH` n'appartient pas à `HUB_UID:HUB_GID` : `sudo scripts/prepare-data-dir.sh` puis `docker compose up -d` |
| `hub-web` unhealthy (autre cause) | `docker compose logs web` ; vérifier que `HUB_DATA_PATH` existe et que le disque n'est pas plein |
| `docker compose config` : « Pool overlaps » | un sous-réseau fixé entre en conflit avec le SI : ne pas charger `compose.vps.yaml` (générique = réseau Docker automatique) |
| Page admin : « Helper certificat indisponible » | normal sans helper (VM générique, TLS par un proxy) ; sinon `systemctl status hub-cert-helper`, socket `/run/hub-cert-helper/helper.sock`, env `/etc/hub-cert-helper.env` |
| « Helper certificat indisponible » **juste après une mise à jour du helper** | le montage du conteneur est périmé si le répertoire de socket a été recréé : `docker compose up -d --force-recreate --no-build web` (un simple `systemctl restart` ne le provoque plus, voir §7) |
| Helper qui refuse de démarrer | `journalctl -u hub-cert-helper -n 50` ; sans Nginx local : `HUB_CERT_RELOAD_NGINX=0` requis |
| Cookie de session non `Secure` / pas de HSTS derrière un proxy | `HUB_TRUSTED_PROXY_CIDRS` ne contient pas l'IP **source** du proxy (les `X-Forwarded-*` sont ignorés par conception) |
| Activation refusée : « validation … » | le message du helper est affiché tel quel (dates, SAN, clé, chaîne) — corriger la paire fournie |
| Activation : « Nginx a refusé la configuration » | soit `nginx -t` échoue réellement (config invalide), soit Nginx est absent et `HUB_CERT_RELOAD_NGINX=1` : passer à `0` |
| « Le certificat servi ne correspond pas » | `nginx -t` puis reload ; vérifier que le vhost Hub pointe sur `active/` |
| 403 depuis l'extérieur | comportement attendu pour une IP hors allowlist (`/etc/nginx/conf.d/00-application-access.conf`) |
| Renouvellement certbot en échec | `sudo certbot renew --cert-name hub.valdev.me --dry-run -v` ; vérifier la location `acme-challenge` du vhost |
| Message « Certbot non détecté » pendant `install-helper.sh` | attendu sur une machine sans Certbot : les certificats fournis manuellement restent installables, seul le renouvellement automatique est absent |
| Session admin perdue après mise à jour | la clé de signature vit dans `<HUB_DATA_PATH>/.secret_key` — vérifier sa présence (0600) |
| Import PKCS#12 : « Impossible d'ouvrir le fichier PKCS#12. Vérifiez le mot de passe. » | mot de passe erroné, bundle corrompu ou fichier qui n'est pas un PKCS#12 (un PEM déposé dans ce champ est signalé explicitement) |
| Import PKCS#12 : « utilise un algorithme non pris en charge » | bundle produit par un outil ancien (RC2/3DES) ; réexporter en AES/PBES2 ou passer par la méthode PEM |
| Import PKCS#12 : « ne contient pas de clé privée » | le bundle ne contient qu'un certificat : utiliser la méthode PEM avec la clé séparée |
| Import refusé : « trop volumineux » | un bundle PKCS#12 fait quelques kilo-octets ; la limite est fixée à 256 Ko |
| Standalone : avertissement de certificat dans le navigateur | normal tant que le certificat définitif n'est pas installé : `/admin/certificats` → PKCS#12 (§7) |
| Standalone : « PID du serveur HTTPS introuvable » | le fichier `HUB_GUNICORN_PIDFILE` (`/tmp/gunicorn.pid`) est absent : vérifier que le conteneur a démarré normalement (`docker logs`) |
| Standalone : activation refusée, « paire précédente restaurée » | le serveur n'a pas présenté la nouvelle paire : vérifier les journaux du conteneur ; le Hub reste disponible avec l'ancienne paire |
| Standalone : `volume de certificats (/certs) non inscriptible` | volume créé hors de l'image (ou montage en lecture seule) : recréer la stack pour laisser Docker initialiser `hub_certs` |
| Standalone : Hub n'apparaît pas sur le réseau d'entreprise | `HUB_DOCKER_NETWORK` saisi sans `HUB_DOCKER_NETWORK_EXTERNAL=true` : Compose a créé un réseau **homonyme** (vérifier `docker network ls`) — ajouter le garde-fou puis redéployer |
| Standalone : « declared as external, but could not be found » | le réseau nommé dans `HUB_DOCKER_NETWORK` n'existe pas (nom ou hôte erroné) : le créer ou corriger la variable |
| Standalone : « no configured subnet contains IP address » | `HUB_IPV4_ADDRESS` n'appartient pas à un sous-réseau du réseau cible : choisir une adresse libre de ce sous-réseau (ou retirer la variable) |

## 14. Contrôles de recette

```bash
.venv/bin/python -m pytest tests/ -q                   # suite complète (Python)
HUB_BASE_URL=http://127.0.0.1:13744 .venv/bin/python tests/browser/acceptance.py
HUB_SCOPE=public HUB_BASE_URL=http://127.0.0.1:13744 .venv/bin/python tests/browser/acceptance.py
bash tests/vm/generic-vm-check.sh                      # VM générique isolée (sans helper/Nginx)
bash tests/vm/standalone-check.sh                      # standalone TLS direct (projet jetable)
STANDALONE_CHECK_BROWSER=1 bash tests/vm/standalone-check.sh   # + recette navigateur réelle
```

`tests/vm/generic-vm-check.sh` déploie un stack jetable (projet Compose
`hub-vmcheck`, port 13807, données dans `/tmp`) avec `compose.yaml` seul : il
vérifie le parcours complet (healthcheck, landing, admin, CRUD, uploads,
catégories, paramètres, page certificats sans helper), l'absence de sous-réseau
imposé, l'UID/GID (dont l'erreur explicite si le répertoire de données
n'appartient pas au bon utilisateur) et le comportement des en-têtes de proxy
(trusted vs non trusted). La production n'est jamais touchée.

`tests/vm/standalone-check.sh` déploie `compose.standalone.yaml` dans un projet
jetable (`hub-standalone-check`, ports 18080/18443) avec des volumes vierges et
vérifie : certificat temporaire servi, HTTPS, création du compte, import PKCS#12
avec chaîne, activation, **certificat réellement présenté**, persistance après
`down`/`up`, refus d'un certificat hors domaine sans bascule, isolation
(lecture seule, capabilities, volumes) et absence de régression de la production.
Avec `STANDALONE_CHECK_BROWSER=1`, la recette navigateur réelle est rejouée
contre ce déploiement (résolution du nom par Chromium, aucun `/etc/hosts` touché).

Depuis le VPS, la recette navigateur de production doit passer par la loopback :
en résolvant le nom publiquement, le navigateur sort par l'IP publique du VPS —
**refusée par l'allowlist**, ce qui est le comportement attendu (403). La règle
de résolution Chromium évite de toucher `/etc/hosts` :

```bash
HUB_BASE_URL=https://hub.valdev.me \
HUB_HOST_RESOLVER="MAP hub.valdev.me 127.0.0.1" \
HUB_SCOPE=public .venv/bin/python tests/browser/acceptance.py
```

La recette navigateur exige Playwright + Chromium (`requirements-dev.txt`) ; sur
un poste neuf : `playwright install chromium`. Variables : `HUB_SCOPE`
(`full` / `public`), `HUB_ADMIN_PASSWORD` (compte existant), `HUB_SKIP_CERT`
(instance locale ou certificat non vérifiable), `HUB_HOST_RESOLVER` (règle de
résolution Chromium, ex. `MAP hub.intra.example 127.0.0.1`), `HUB_SHOTS_DIR`
(captures de validation).
