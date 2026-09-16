# SNS Hub — Exploitation

Toutes les commandes se lancent depuis le workspace canonique :

```bash
cd /home/tetrax/workspace/hub
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

## 4. Certificat TLS

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

1. `sudo scripts/install-helper.sh` (installe `/opt`, le service, l'env, le hook certbot) ;
2. obtenir la paire (certbot webroot ou PKI interne) ;
3. `sudo sh -c 'set -a; . /etc/hub-cert-helper.env; set +a; python3 /opt/hub-cert-helper/scripts/hub_cert_helper.py install --cert <fullchain.pem> --key <privkey.pem>'`
   → validation, activation, `nginx -t`, reload, vérification du certificat servi.

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

## 5. Sauvegarde et restauration

```bash
sudo ./scripts/backup.sh                 # /home/tetrax/backups/hub/ (10 archives conservées)
HUB_BACKUP_DIR=/chemin sudo ./scripts/backup.sh
```

Contenu : `hub.sqlite` (copie cohérente), `uploads/`, `secret_key`,
`MANIFEST.txt`, plus une archive séparée des certificats (`hub-certificates-*.tar.gz`).

### Restauration

```bash
sudo tar -xzf /home/tetrax/backups/hub/hub-backup-<stamp>.tar.gz -C /tmp/hub-restore
sudo install -d -o 1000 -g 1000 -m 0755 runtime/data
sudo install -o 1000 -g 1000 -m 0644 /tmp/hub-restore/hub.sqlite runtime/data/hub.sqlite
sudo cp -a /tmp/hub-restore/uploads/. runtime/data/uploads/
sudo install -o 1000 -g 1000 -m 0600 /tmp/hub-restore/secret_key runtime/data/.secret_key
sudo chown -R 1000:1000 runtime/data
docker compose up -d --no-build
curl -s http://127.0.0.1:13744/healthz
```

Certificats : restaurer `hub-certificates-*.tar.gz` dans `/var/lib/hub/`
(le lien `active` est inclus) puis `sudo nginx -t && sudo systemctl reload nginx`
(sous le verrou infra si d'autres changements nginx sont en cours).

## 6. Reconstruction complète (reprise sur une nouvelle machine)

1. Cloner `https://github.com/Tetrax/hub` dans `/home/tetrax/workspace/hub` ;
2. `sudo install -d -o 1000 -g 1000 -m 0755 runtime/data runtime/data/uploads` ;
3. `sudo scripts/install-helper.sh` ;
4. config Nginx `deploy/nginx/hub.valdev.me.conf` → `sites-available` + symlink →
   `sudo nginx -t && sudo systemctl reload nginx` ;
5. certificat : certbot (`--webroot -w /var/www/hub-acme -d hub.valdev.me`) puis
   amorçage helper (section 4) ;
6. `./scripts/deploy.sh` ou `HUB_IMAGE_TAG=<sha> docker compose up -d --no-build` ;
7. restaurer la sauvegarde (section 5) si nécessaire.

## 7. Dépannage

| Symptôme | Piste |
|---|---|
| `hub-web` unhealthy | `docker compose logs web` ; vérifier `runtime/data` inscriptible par uid 1000 |
| Page admin : « Helper certificat indisponible » | `systemctl status hub-cert-helper` ; socket `/run/hub-cert-helper/helper.sock` ; env `/etc/hub-cert-helper.env` |
| Activation refusée : « validation … » | le message du helper est affiché tel quel (dates, SAN, clé, chaîne) — corriger la paire fournie |
| « Le certificat servi ne correspond pas » | `nginx -t` puis reload ; vérifier que le vhost Hub pointe sur `active/` |
| 403 depuis l'extérieur | comportement attendu pour une IP hors allowlist (`/etc/nginx/conf.d/00-application-access.conf`) |
| Renouvellement certbot en échec | `sudo certbot renew --cert-name hub.valdev.me --dry-run -v` ; vérifier la location `acme-challenge` du vhost |
| Session admin perdue après mise à jour | la clé de signature vit dans `runtime/data/.secret_key` — vérifier sa présence (0600) |

## 8. Contrôles de recette

```bash
.venv/bin/python -m pytest tests/ -q                   # suite complète
HUB_BASE_URL=http://127.0.0.1:13744 .venv/bin/python tests/browser/acceptance.py
```

La recette navigateur exige Playwright + Chromium (`requirements-dev.txt`) ; sur
un poste neuf : `playwright install chromium`.
