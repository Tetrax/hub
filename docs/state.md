# SNS Hub — État du projet

Dernière mise à jour : 2026-09-16 (UTC)
Statut : **V1.1 déployée en production — recette passée, aucune action ouverte côté exploitation**.

> Ce fichier est le point de reprise opérationnel du projet. Il décrit ce qui est
> déployé, comment le vérifier, et ce qui reste à faire. Les détails techniques
> vivent dans `architecture.md`, les choix dans `decisions.md`, les procédures
> dans `operations.md`.

## Version et périmètre

- **V1.1** : catégories administrables + thème clair/sombre (voir D11, D12).
- V1 : landing catalogue, administration complète, gestion du certificat TLS,
  sauvegarde/restauration, recette navigateur.

## Production

| Élément | Valeur |
|---|---|
| URL | https://hub.valdev.me |
| Conteneur | `hub-web` (Compose projet `hub`, profil par défaut) |
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

## Reprise après incident

1. `sudo ./scripts/backup.sh` puis inspecter `/home/tetrax/backups/hub/`.
2. Redéployer un commit connu : `git checkout <sha> && ./scripts/deploy.sh`
   (l'image `hub:previous` conserve la version précédente).
3. Base : restaurer `hub.sqlite` depuis une archive (voir `operations.md`) ;
   le conteneur applique les migrations manquantes à son démarrage.
4. Certificat : `/admin/certificats` (remplacement manuel) ou hook Certbot
   (`certbot renew --dry-run` pour tester).

## Prochaines étapes (non engagées)

- Planification automatique de `scripts/backup.sh` (timer systemd) si souhaité.
- Catégories : icônes/couleurs par catégorie, regroupements sur la landing —
  à décider seulement si le besoin apparaît.
- Thème : option « suivre le système » explicitement affichée (aujourd'hui c'est
  le comportement par défaut en l'absence de choix), si demandé.
