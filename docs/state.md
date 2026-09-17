# SNS Hub — État du projet

Dernière mise à jour : 2026-09-17 (UTC)
Statut : **V1.6.1 livrée — transport email administrable (SMTP ou Microsoft 365
configurable dans `/admin/security`, secrets hors base, test d'envoi)**, en plus
de la surveillance Trivy (ingestion de l'artefact CI, baseline/delta, alertes sur
changement), du branding configurable, de la vue Liste et du contrôle Trivy en
CI ; aucune action ouverte.

> Ce fichier est le point de reprise opérationnel du projet. Il décrit ce qui est
> déployé, comment le vérifier, et ce qui reste à faire. Les détails techniques
> vivent dans `architecture.md`, les choix dans `decisions.md`, les procédures
> dans `operations.md`.

## Version et périmètre

- **V1.6.1 (2026-09-17)** : **transport email administrable** — le choix
  **SMTP** ou **Microsoft 365 (Graph)** se fait dans `/admin/security`, avec les
  paramètres saisis dans la webapp, un **test d'envoi** réel et une prise en
  compte immédiate (aucun redémarrage, aucune variable Portainer). Les secrets
  (mot de passe SMTP, secret client Microsoft 365) sont stockés **hors base**
  dans `secrets/` du répertoire de données (0600), jamais réaffichés (provenance
  seulement), remplaçables et supprimables explicitement ; les variables
  `HUB_SMTP_PASSWORD` / `HUB_MICROSOFT_CLIENT_SECRET` ne servent que de
  bootstrap (l'admin est prioritaire). Les alertes Trivy utilisent le transport
  sélectionné ; migration V1.6 → V1.6.1 purement additive (voir D23,
  exploitation §16).
- **V1.6 (2026-09-17)** : **surveillance de l'image par le Hub** — il **consomme**
  l'artefact `trivy-report` de la CI (jamais de scan côté Hub, aucun accès
  Docker), valide strictement le rapport, publie un état (baseline silencieuse,
  puis delta : apparitions, disparitions, changements de sévérité), l'affiche dans
  `/admin/security` (état + vulnérabilités actionnables) et n'envoie **qu'un seul
  email — uniquement en cas de changement** (filtres par sévérité/type ; renvoi
  possible après échec). Planification interne (thread + verrou inter-process,
  horaire au plus ; aucun service supplémentaire, standalone inchangé).
  **Désactivée par défaut** ; activable seulement avec `HUB_GITHUB_TOKEN`
  (lecture seule, portée `Actions: Read`) et un transport email complet — jamais
  en base ni rendus (voir D22, exploitation §16).
- **CI (2026-09-17)** : **GitHub Actions** — `.github/workflows/ci.yml` : job
  `tests` (suite pytest complète, bloquant) puis job `security-scan` (**Trivy
  informatif** sur l'image réellement produite : paquets OS + bibliothèques
  Python, `HIGH,CRITICAL` corrigibles uniquement, `exit-code: 0`, artefact
  `trivy-report` 30 jours, résumé d'étape et annotation), scan **quotidien** de
  `main` à 05:23 UTC et lancement manuel (`workflow_dispatch`) ; Trivy n'entre
  jamais dans l'image/le runtime, aucun secret requis (voir D21, exploitation
  §15). Aucun changement produit : version applicative et production inchangées.
- **V1.5** : évolution UI ciblée — **branding du header configurable**
  (`HUB_BRAND_LABEL`, « HUB » par défaut, purement visuel, validé et échappé,
  voir D19) et **deux vues du catalogue** : Cartes (par défaut, comportement
  historique) et **Liste dense sans captures**, avec bascule accessible,
  préférence par navigateur (`localStorage`, clé `hub_catalog_view`) appliquée
  avant le premier rendu et filtres/recherche strictement partagés (voir D20).
- **V1.4** : déploiement **standalone** Portainer — `compose.standalone.yaml`,
  **un seul conteneur qui sert HTTPS directement** (aucun proxy, aucun helper,
  aucun socket Docker), certificat temporaire de bootstrap au premier démarrage,
  remplacement du certificat depuis la page web avec rechargement du serveur et
  vérification du certificat réellement servi (voir D16, D17).
- **V1.4.1** : rattachement **optionnel** du standalone à un **réseau Docker
  existant** (`HUB_DOCKER_NETWORK`, `HUB_DOCKER_NETWORK_EXTERNAL`) et **IPv4
  statique** (`HUB_IPV4_ADDRESS`) — entièrement par variables, aucune valeur
  propre à un environnement dans le dépôt, déploiement standard inchangé (D18).
- **V1.3** : portabilité — `compose.yaml` générique, surcharge `compose.vps.yaml`,
  configuration par variables (`.env`), helper certificat et Certbot optionnels,
  recette « VM générique » isolée (voir D14, D15).
- **V1.2** : import de certificats PKCS#12 / PFX (et PEM/DER) sur la page
  Certificats, sans changement du pipeline helper (voir D13).
- **V1.1** : catégories administrables + thème clair/sombre (voir D11, D12).
- V1 : landing catalogue, administration complète, gestion du certificat TLS,
  sauvegarde/restauration, recette navigateur.

## Production

| Élément | Valeur |
|---|---|
| URL | https://hub.valdev.me |
| Conteneur | `hub-web` (Compose projet `hub`, `COMPOSE_FILE=compose.yaml:compose.vps.yaml`) |
| Image | `hub:<SHA>` (SHA = HEAD du dépôt au déploiement) |
| Exposition | `127.0.0.1:13744` → `8000` (gunicorn, 2 workers) |
| Données | `runtime/data/hub.sqlite` (WAL), `runtime/data/uploads/`, `runtime/data/.secret_key` |
| Certificat | Let's Encrypt servi depuis `/var/lib/hub/certificates/active/` (helper root) |
| Helper | `hub-cert-helper.service` (actif, enabled) |

Version applicative : `app/__init__.py` (`__version__`), affichée dans le pied de
page et `/healthz`.

## Vérifications rapides (post-déploiement)

```bash
curl -s -o /dev/null -w '%{http_code}\n' --resolve hub.valdev.me:443:127.0.0.1 https://hub.valdev.me/
curl -s --resolve hub.valdev.me:443:127.0.0.1 https://hub.valdev.me/healthz
curl -s --resolve hub.valdev.me:443:127.0.0.1 https://hub.valdev.me/ | grep -o 'class="brand-name">[^<]*<'
docker compose ps && docker inspect -f '{{.State.Health.Status}}' hub-web
sudo nginx -t && systemctl is-active hub-cert-helper.service
cd /home/tetrax/workspace/hub && .venv/bin/python -m pytest tests/ -q
HUB_BASE_URL=http://127.0.0.1:13744 HUB_SCOPE=public .venv/bin/python tests/browser/acceptance.py
gh run list --workflow=ci.yml --limit 3          # état du contrôle Trivy (CI)
gh workflow run ci.yml                            # scan de sécurité manuel
```

## État fonctionnel

- **Catalogue** : 6 applications publiées (FortiUpgrade, FortiFlow, FortiFlow2,
  FortiAnonymous, Vysion, Portfolio), captures réelles en WebP.
- **Catégories** : `Autres` (repli, protégée), `Fortinet`, `Sécurité` —
  administrables (création, renommage, ordre, suppression avec réassignation).
- **Thème** : sombre (référence) / clair, bascule mémorisée par navigateur,
  préférence système respectée à la première visite.
- **Affichage du catalogue (V1.5)** : vue **Cartes** par défaut (comportement
  inchangé) et vue **Liste** dense sans captures ; bascule accessible
  (clavier, `aria-pressed`) dans la barre de résultats, préférence par
  navigateur (`localStorage`, clé `hub_catalog_view`) appliquée avant le
  premier rendu, recherche et catégories strictement identiques dans les deux
  vues.
- **Branding (V1.5)** : libellé du header configurable par `HUB_BRAND_LABEL`
  (« HUB » par défaut ; purement visuel). Le VPS de production reste sans la
  variable.
- **Contrôle de sécurité (CI, D21)** : scan Trivy quotidien + push/PR sur l'image
  réelle, **informatif** (artefact `trivy-report`, résumé dans le run). État au
  2026-09-17 : **13 vulnérabilités corrigibles (3 CRITICAL · 10 HIGH), toutes
  dans des paquets OS Debian** de l'image de base (`perl-base`, `gzip`,
  `libpcre2-8-0`, `libsqlite3-0`) — **0 côté Python** ; la base du jour porte
  encore ces versions, le finding sera résolu par un rafraîchissement du digest
  `python:3.12-slim` quand Debian publiera les correctifs.
- **Surveillance de l'image (V1.6, D22 — transport V1.6.1, D23)** : le Hub
  **consomme** l'artefact `trivy-report` (aucun scan côté Hub) et affiche l'état
  dans `/admin/security` — baseline silencieuse à la première ingestion, puis
  delta (apparitions, disparitions, changements de sévérité) ; **un seul email
  par synchronisation, uniquement en cas de changement** ; synchronisation
  interne horaire (thread + verrou inter-process, standalone inchangé) ;
  **désactivée par défaut** (nécessite `HUB_GITHUB_TOKEN` en lecture seule et un
  transport email complet). **Transport email (V1.6.1)** : SMTP ou Microsoft 365
  (Graph, `Mail.Send`), configurable dans l'admin avec test d'envoi ; secrets
  dans `runtime/data/secrets/` (0600, hors base, provenance affichée,
  `HUB_SMTP_PASSWORD`/`HUB_MICROSOFT_CLIENT_SECRET` en bootstrap seulement).
  État au 2026-09-17 : validée en réel sur le run CI `35253281173` (baseline
  3 CRITICAL / 10 HIGH, idempotence vérifiée) ; transport V1.6.1 vérifié sur
  instance locale (SMTP réel factice + Microsoft 365 simulé) et en production
  après déploiement.
- **Administration** : compte unique créé au premier accès (`/admin/setup`),
  sessions serveur, CSRF, verrouillage après échecs.
- **Migration de base** : schéma en `user_version = 3` (migration V1.1 appliquée
  en production le 2026-09-16, sauvegarde préalable conservée ; V1.6 ajoute les
  tables `security_state`/`security_events`, additives).

### Certificat TLS en production (V1.2)

- Paire active : Let's Encrypt `CN=hub.valdev.me`, expire le **2026-12-15**,
  empreinte SHA-256 `36:86:21:E8:CB:3F:D2:B0:CD:0B:FB:7E:D1:D1:3E:78:C1:CC:0D:15:B4:B0:97:6B:25:52:AE:46:00:A1:AD:31`,
  génération `.active-66ae25f978498c87`, `servedMatches = true`.
- Imports : deux méthodes (`PKCS#12 / PFX` par défaut, `PEM / CRT — avancé`) ;
  aucun certificat de test n'a remplacé la paire de production (voir D13 et
  `docs/operations.md` §7 pour la limite des 256 Ko et l'interaction Certbot).

## Trois profils de déploiement (V1.4)

Un seul code applicatif, une seule image, un seul dépôt :

| Profil | Infrastructure | Configuration |
|---|---|---|
| VPS de production | Nginx local + helper root + Certbot | `COMPOSE_FILE=compose.yaml:compose.vps.yaml` (le `.env` du VPS porte aussi `HUB_BACKUP_DIR=/home/tetrax/backups/hub`) |
| Standalone Portainer (**V1.4.1**) | **Aucun prérequis** : le conteneur sert HTTPS lui-même | `compose.standalone.yaml` + `HUB_HOSTNAME=<FQDN>` (c'est tout) ; option : `HUB_DOCKER_NETWORK` / `HUB_DOCKER_NETWORK_EXTERNAL` / `HUB_IPV4_ADDRESS` pour rejoindre un réseau existant (D18) |
| VM derrière un proxy / LB | TLS terminé en amont | `compose.yaml` seul + `HUB_TRUSTED_PROXY_CIDRS=<IP du proxy>` |

**Standalone** : volumes nommés `hub_data` (base, uploads, clé de session) et
`hub_certs` (générations + paire active) ; certificat temporaire auto-signé au
premier démarrage, puis installation du PKCS#12 de la PKI depuis
`/admin/certificats` — le serveur est rechargé par `SIGHUP` et le certificat
réellement présenté est vérifié, avec rollback automatique en cas d'échec.
Recette dédiée : `bash tests/vm/standalone-check.sh` (isolée, production intacte).

Le répertoire de données doit appartenir à `HUB_UID:HUB_GID` :
`sudo scripts/prepare-data-dir.sh` (erreur explicite et actionnable au démarrage
sinon). Recette dédiée : `bash tests/vm/generic-vm-check.sh` (isolée, sans
Nginx/Certbot/helper) et `sudo bash tests/vm/helper-check.sh` (helper avec et
sans Nginx, dans un bac à sable `/tmp`).

## Reprise après incident

1. `sudo ./scripts/backup.sh` puis inspecter la destination (`HUB_BACKUP_DIR` du
   `.env`, `/home/tetrax/backups/hub` sur le VPS).
2. Redéployer un commit connu : `git checkout <sha> && ./scripts/deploy.sh`
   (l'image `hub:previous` conserve la version précédente).
3. Base : restaurer `hub.sqlite` depuis une archive (voir `operations.md` §8) ;
   le conteneur applique les migrations manquantes à son démarrage.
4. Certificat : `/admin/certificats` (remplacement manuel) ou hook Certbot
   (`certbot renew --dry-run` pour tester).

## Prochaines étapes (non engagées)

- Planification automatique de `scripts/backup.sh` (timer systemd) si souhaité.
- Sauvegarde du standalone : les volumes `hub_data`/`hub_certs` se sauvegardent
  par `docker run --rm -v …:/data …` (à documenter si le besoin apparaît).
- Redirection HTTP/80 → HTTPS en standalone : non servie par choix (une seule
  écoute par serveur, voir D16) ; à rouvrir seulement si un besoin réel apparaît.
- Catégories : icônes/couleurs par catégorie, regroupements sur la landing —
  à décider seulement si le besoin apparaît.
- Thème : option « suivre le système » explicitement affichée (aujourd'hui c'est
  le comportement par défaut en l'absence de choix), si demandé.
