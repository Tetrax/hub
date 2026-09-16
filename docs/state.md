# SNS Hub — État du projet

Dernière mise à jour : 2026-09-16 (UTC)
Statut : **V1.3 déployée en production — portabilité multi-environnement, aucune action ouverte**.

> Ce fichier est le point de reprise opérationnel du projet. Il décrit ce qui est
> déployé, comment le vérifier, et ce qui reste à faire. Les détails techniques
> vivent dans `architecture.md`, les choix dans `decisions.md`, les procédures
> dans `operations.md`.

## Version et périmètre

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
docker compose ps && docker inspect -f '{{.State.Health.Status}}' hub-web
sudo nginx -t && systemctl is-active hub-cert-helper.service
cd /home/tetrax/workspace/hub && .venv/bin/python -m pytest tests/ -q
HUB_BASE_URL=http://127.0.0.1:13744 HUB_SCOPE=public .venv/bin/python tests/browser/acceptance.py
```

## État fonctionnel

- **Catalogue** : 6 applications publiées (FortiUpgrade, FortiFlow, FortiFlow2,
  FortiAnonymous, Vysion, Portfolio), captures réelles en WebP.
- **Catégories** : `Autres` (repli, protégée), `Fortinet`, `Sécurité` —
  administrables (création, renommage, ordre, suppression avec réassignation).
- **Thème** : sombre (référence) / clair, bascule mémorisée par navigateur,
  préférence système respectée à la première visite.
- **Administration** : compte unique créé au premier accès (`/admin/setup`),
  sessions serveur, CSRF, verrouillage après échecs.
- **Migration de base** : schéma en `user_version = 2` (migration V1.1 appliquée
  en production le 2026-09-16, sauvegarde préalable conservée).

### Certificat TLS en production (V1.2)

- Paire active : Let's Encrypt `CN=hub.valdev.me`, expire le **2026-12-15**,
  empreinte SHA-256 `36:86:21:E8:CB:3F:D2:B0:CD:0B:FB:7E:D1:D1:3E:78:C1:CC:0D:15:B4:B0:97:6B:25:52:AE:46:00:A1:AD:31`,
  génération `.active-66ae25f978498c87`, `servedMatches = true`.
- Imports : deux méthodes (`PKCS#12 / PFX` par défaut, `PEM / CRT — avancé`) ;
  aucun certificat de test n'a remplacé la paire de production (voir D13 et
  `docs/operations.md` §7 pour la limite des 256 Ko et l'interaction Certbot).

## Portabilité (V1.3)

Trois profils, **un seul code applicatif** et un seul dépôt :

| Profil | Infrastructure | Configuration |
|---|---|---|
| VPS de production | Nginx local + helper root + Certbot | `COMPOSE_FILE=compose.yaml:compose.vps.yaml` (le `.env` du VPS porte aussi `HUB_BACKUP_DIR=/home/tetrax/backups/hub`) |
| VM entreprise derrière un proxy / LB | TLS terminé en amont, pas de Nginx ni de helper | `compose.yaml` seul + `HUB_TRUSTED_PROXY_CIDRS=<IP du proxy>` |
| VM en accès direct | Docker seul | `compose.yaml` seul + `HUB_BIND_IP=0.0.0.0` (+ pare-feu) |

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
- HTTPS 100 % autonome (proxy embarqué) : évolution séparée, seulement si un
  besoin réel apparaît (voir l'audit de portabilité et D14).
- Catégories : icônes/couleurs par catégorie, regroupements sur la landing —
  à décider seulement si le besoin apparaît.
- Thème : option « suivre le système » explicitement affichée (aujourd'hui c'est
  le comportement par défaut en l'absence de choix), si demandé.
