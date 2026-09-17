# SNS Hub

**Tous vos outils. Un seul accès.**

SNS Hub est le portail interne SNS Security : il présente les applications
internes (Fortinet, sécurité, utilitaires) sur une seule page et fournit leur
administration — catalogue, screenshots, ordre, visibilité, statut.

- **Production** : https://hub.valdev.me
- **Administration** : https://hub.valdev.me/admin
- **Dépôt** : https://github.com/Tetrax/hub

Le Hub est un **catalogue / launcher** : il référence les applications et
ouvre leurs URLs ; il ne les proxifie pas, ne les surveille pas et n'exécute
aucune requête vers elles.

## Fonctionnalités

- Landing page légère (rendu serveur, sans framework JS) : cartes avec capture
  réelle, catégorie, statut discret, recherche instantanée et filtre par
  catégorie (fonctionnels sans JavaScript), responsive desktop/tablette/mobile.
- Administration : CRUD des applications, ordre d'affichage, masquage immédiat,
  téléversement de screenshots (PNG/JPEG/WebP, validés par magic bytes),
  paramètres du portail, rotation du mot de passe.
- Catégories administrables (V1.1) : entité en base avec usage, ordre d'affichage,
  renommage, création rapide depuis le formulaire d'une application et
  suppression sûre (réassignation obligatoire ; repli « Autres » protégé). Les
  filtres du portail en découlent automatiquement.
- Thème clair / sombre (V1.1) : bascule discrète sur le portail et dans
  l'administration, choix mémorisé par navigateur, préférence système respectée
  à la première visite, aucun flash au chargement. La direction artistique
  sombre reste la référence.
- Gestion du certificat TLS : état complet de la paire active et remplacement
  en deux temps (valider puis activer) avec bascule atomique, rechargement du
  serveur, vérification du certificat réellement servi et rollback — sur le VPS
  (Nginx via le helper root) comme en standalone (serveur HTTPS du conteneur).
- Import de certificats (V1.2) : **PKCS#12 / PFX** (`.p12`, `.pfx`, mot de passe
  optionnel) lu en mémoire par l'application — un seul fichier à fournir, la
  chaîne et le certificat feuille sont extraits automatiquement (racine omise),
  le secret n'est jamais conservé ; mode **PEM / CRT avancé** conservé, avec
  détection réelle **DER**. Même pipeline de validation/activation que la V1.
- Portabilité (V1.3) : le **même dépôt** se déploie sur le VPS (Nginx + helper +
  Certbot) ou sur n'importe quelle VM Linux avec Docker — y compris **derrière
  un reverse proxy d'entreprise** (TLS géré en amont) et **sans Nginx, sans
  Certbot, sans helper**. `compose.yaml` est générique, `compose.vps.yaml` porte
  les spécificités du VPS, `.env` la configuration locale (`HUB_BIND_IP`,
  `HUB_PORT`, `HUB_UID/GID`, `HUB_TRUSTED_PROXY_CIDRS`…).
- **Déploiement standalone (V1.4)** : `compose.standalone.yaml` — **un seul
  conteneur** qui sert HTTPS **directement** (aucun Nginx, aucun Caddy, aucun
  proxy, aucun helper, aucun socket Docker), pensé pour Portainer
  (*Stacks → Add stack → Repository*). Au premier démarrage, un **certificat
  temporaire auto-signé** est généré pour le nom DNS fourni : le Hub est
  immédiatement joignable en HTTPS, on crée son compte, puis on installe le
  certificat définitif (**PKCS#12 de la PKI**) depuis *Administration →
  Certificats* — **sans SSH et sans redémarrage** (le serveur est rechargé et le
  certificat réellement servi est vérifié, avec rollback en cas d'échec).
- **Branding configurable (V1.5)** : le libellé affiché à côté du logo SNS dans
  le header (`SNS | <libellé>`) est réglé par `HUB_BRAND_LABEL` — `HUB` par
  défaut, donc aucune installation existante ne change. Purement visuel :
  aucune conséquence sur le hostname, le certificat, la base, les sessions ou
  les URLs ; texte simple (espaces normalisés, 40 caractères au plus, échappé à
  l'affichage).
- **Deux vues du catalogue (V1.5)** : **Cartes** (par défaut — captures réelles,
  comportement historique inchangé) et **Liste** (dense : nom, catégorie,
  statut, description courte et CTA, sans capture, pensée pour plusieurs
  dizaines d'applications). La bascule est discrète (barre de résultats),
  accessible au clavier (`aria-pressed`), mémorisée par navigateur
  (`localStorage`, clé `hub_catalog_view`) et appliquée avant le premier rendu
  (aucun clignotement) ; recherche et filtres de catégories sont strictement
  identiques dans les deux vues (un seul moteur, sans JavaScript la vue Cartes
  reste le comportement par défaut).
- **Transport email administrable (V1.6.1) et secrets administrables (V1.6.2)** :
  depuis *Administration → Sécurité*, choisir **SMTP** ou **Microsoft 365**
  (Microsoft Graph), saisir les paramètres puis **tester l'envoi** réel — sans
  redémarrage, sans redéploiement et sans variable Portainer. Les secrets
  (jeton GitHub de la surveillance, mot de passe SMTP, secret client Microsoft
  365) sont stockés hors base, dans un stockage dédié du répertoire de données
  (fichiers 0600), ne sont jamais réaffichés (état « configuré / non
  configuré »), se remplacent ou se suppriment explicitement ; les variables
  d'environnement ne servent que de **bootstrap** (le secret administré est
  toujours prioritaire). La surveillance Trivy s'active ainsi **entièrement
  depuis la webapp** et ses alertes utilisent le transport sélectionné.

## Architecture

```
Profil VPS        : Nginx (TLS, allowlist IP) → conteneur hub-web (SQLite)
                                            ↕ socket Unix
                                          hub-cert-helper (root)
Profil générique  : proxy/LB d'entreprise (TLS) → conteneur hub-web (SQLite)
                    (aucun Nginx, aucun helper sur l'hôte)
Profil standalone : navigateur ── HTTPS ──▶ conteneur hub-web   (TLS direct,
                    SQLite + certificats dans des volumes Docker nommés)
```

Détails : [`docs/architecture.md`](docs/architecture.md) ·
Exploitation : [`docs/operations.md`](docs/operations.md) ·
Décisions : [`docs/decisions.md`](docs/decisions.md) ·
État : [`docs/state.md`](docs/state.md).

## Développement

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest tests/ -q

# exécution locale (données dans ./runtime/data)
HUB_DATA_DIR=./runtime/data HUB_TLS_HOSTNAME=hub.valdev.me \
  .venv/bin/python -c "from app import create_app; create_app().run(host='127.0.0.1', port=8000)"
```

Recette navigateur (Playwright/Chromium) :

```bash
playwright install chromium   # une seule fois par poste
HUB_BASE_URL=http://127.0.0.1:8000 .venv/bin/python tests/browser/acceptance.py
```

## Intégration continue (GitHub Actions)

`.github/workflows/ci.yml` — déclenché par `push` sur `main`, `pull_request`,
un scan quotidien de `main` (05:23 UTC) et un lancement manuel
(`workflow_dispatch`) :

| Job | Rôle | Bloquant |
|---|---|---|
| `tests` | suite pytest complète (Python 3.12) | **oui** |
| `security-scan` | construction de l'image réelle (aucun push) puis **scan Trivy** — paquets OS + bibliothèques Python, sévérité `HIGH,CRITICAL`, `ignore-unfixed: true` (uniquement les vulnérabilités corrigibles) | **non** — contrôle informatif |

Le scan **ne fait jamais échouer le run** (`exit-code: 0`) : les résultats sont
publiés dans le résumé d'étape, une annotation globale et l'artefact
`trivy-report` (`trivy.json`, 30 jours). Un rapport absent ou illisible est
signalé explicitement — jamais lu comme « aucune vulnérabilité ». Aucun secret
n'est nécessaire, et Trivy n'est **jamais** installé dans l'image, le runtime,
sur le VPS ou dans Portainer. Scanner manuellement : *Actions → CI → Run
workflow*, ou `gh workflow run ci.yml`.

## Surveillance de l'image (Trivy)

Le Hub **consomme** l'artefact `trivy-report` produit par la CI (ci-dessus) : il
ne scanne rien, n'inspecte pas Docker et ne lance aucun Trivy. Depuis
`/admin/security` (strictement administrateur) :

- **état de l'image** : compteurs CRITICAL/HIGH, dernier scan (signalé « rapport
  ancien » au-delà de 48 h), commit, run GitHub, image ;
- **vulnérabilités actionnables** (HIGH/CRITICAL corrigibles) avec versions
  installée/corrigée et lien d'avis si le rapport en fournit un ;
- **baseline silencieuse** à la première ingestion, puis **delta** : apparitions,
  disparitions (« vulnérabilité non détectée dans la nouvelle image »),
  changements de sévérité ;
- **un email au maximum par synchronisation**, uniquement en cas de changement
  (jamais de mail quotidien), désactivable indépendamment de la surveillance.

La synchronisation est **interne** (une fois par heure au plus, verrou
inter-process ; aucun service ni conteneur supplémentaire, y compris en
standalone) et **désactivée par défaut**. Pour l'activer : un **jeton GitHub en
lecture seule** (portée `Actions: Read`) — obligatoire, le téléchargement
d'artefact l'exige même pour un dépôt public — et un **transport email
complet**, le tout **configuré dans l'admin** (`/admin/security`). Les secrets
peuvent aussi venir du déploiement (`HUB_GITHUB_TOKEN`, `HUB_SMTP_PASSWORD`,
`HUB_MICROSOFT_CLIENT_SECRET`) comme simple **bootstrap** : un secret enregistré
dans la webapp est toujours prioritaire. Détails : `docs/operations.md` §16,
décisions D22 à D24.

## Déploiement

```bash
./scripts/deploy.sh                     # commit courant → image SHA → conteneur → healthcheck
sudo ./scripts/backup.sh                # sauvegarde base + uploads + certificats
```

Installation sur une nouvelle VM (Docker + Compose, sans Nginx/Certbot/helper) :

```bash
git clone https://github.com/Tetrax/hub && cd hub
cp .env.example .env                    # ajuster HUB_BIND_IP, HUB_PORT, HUB_UID/GID…
sudo scripts/prepare-data-dir.sh        # propriétaire du répertoire de données
docker compose up -d --build
curl -s http://127.0.0.1:13744/healthz  # {"status":"ok","version":"1.5.0",…}
```

Sur le VPS, `.env` porte `COMPOSE_FILE=compose.yaml:compose.vps.yaml` : les
spécificités locales (sous-réseau fixé, proxy de confiance, hostname, socket du
helper) viennent de la surcharge versionnée. Variantes (proxy d'entreprise,
Portainer, hors ligne, restauration) : [`docs/operations.md`](docs/operations.md) §9–§12.

### Déploiement standalone (Portainer — HTTPS direct, un conteneur)

1. DNS : `hub.sns-security.lan` → IP de la VM (préparation réseau habituelle) ;
2. Portainer → **Stacks** → **Add stack** → **Repository** :
   - **Repository URL** : `https://github.com/Tetrax/hub`
   - **Repository reference** : `refs/heads/main`
   - **Compose path** : `compose.standalone.yaml`
   - **Environment variables** : `HUB_HOSTNAME=hub.sns-security.lan`
     (et, si besoin, `HUB_HTTPS_PORT=443`) ;
   - personnalisation du header (**optionnel**) : `HUB_BRAND_LABEL=<libellé>`
     (`HUB` par défaut ; purement visuel) ;
   - rattachement à un réseau Docker existant (**optionnel**) :
     `HUB_DOCKER_NETWORK=<nom du réseau>` · `HUB_DOCKER_NETWORK_EXTERNAL=true`
     · `HUB_IPV4_ADDRESS=<adresse>` — à laisser vides pour un déploiement
     standard (Docker attribue alors l'adresse). Aucune valeur par défaut
     propre à un environnement dans le dépôt ;
3. **Deploy the stack** → attendre `healthy` ;
4. ouvrir `https://hub.sns-security.lan` (accepter le certificat temporaire) ;
5. créer le compte administrateur ;
6. **Administration → Certificats** → importer le **PKCS#12** fourni par la DSI
   (fichier + mot de passe) → *Valider et installer*.

Aucun `ssh`, `sudo`, `mkdir`, `chown`, `systemctl`, `nginx`, `certbot` n'est
nécessaire : les volumes Docker (`hub_data`, `hub_certs`) sont créés et
initialisés automatiquement.

Rollback : redéployer l'image du commit précédent
(`HUB_IMAGE_TAG=<sha> docker compose up -d --no-build`), données persistantes
compatibles (voir `docs/operations.md`).

## Sécurité

Sessions serveur (cookie HttpOnly/Secure/SameSite=Strict, jeton haché), scrypt,
CSRF, contrôle d'origine, verrouillage anti-brute-force, en-têtes de sécurité,
CSP stricte, conteneur en lecture seule non-root, clé privée 0600 root jamais
exposée, aucune requête sortante vers le catalogue.
