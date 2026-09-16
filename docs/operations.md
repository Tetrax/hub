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

## 7. Certificat TLS

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

## 8. Sauvegarde et restauration

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

## 9. Reconstruction complète (reprise sur une nouvelle machine)

1. Cloner `https://github.com/Tetrax/hub` dans `/home/tetrax/workspace/hub` ;
2. `sudo install -d -o 1000 -g 1000 -m 0755 runtime/data runtime/data/uploads` ;
3. `sudo scripts/install-helper.sh` ;
4. config Nginx `deploy/nginx/hub.valdev.me.conf` → `sites-available` + symlink →
   `sudo nginx -t && sudo systemctl reload nginx` ;
5. certificat : certbot (`--webroot -w /var/www/hub-acme -d hub.valdev.me`) puis
   amorçage helper (section 4) ;
6. `./scripts/deploy.sh` ou `HUB_IMAGE_TAG=<sha> docker compose up -d --no-build` ;
7. restaurer la sauvegarde (section 5) si nécessaire.

## 10. Dépannage

| Symptôme | Piste |
|---|---|
| `hub-web` unhealthy | `docker compose logs web` ; vérifier `runtime/data` inscriptible par uid 1000 |
| Page admin : « Helper certificat indisponible » | `systemctl status hub-cert-helper` ; socket `/run/hub-cert-helper/helper.sock` ; env `/etc/hub-cert-helper.env` |
| Activation refusée : « validation … » | le message du helper est affiché tel quel (dates, SAN, clé, chaîne) — corriger la paire fournie |
| « Le certificat servi ne correspond pas » | `nginx -t` puis reload ; vérifier que le vhost Hub pointe sur `active/` |
| 403 depuis l'extérieur | comportement attendu pour une IP hors allowlist (`/etc/nginx/conf.d/00-application-access.conf`) |
| Renouvellement certbot en échec | `sudo certbot renew --cert-name hub.valdev.me --dry-run -v` ; vérifier la location `acme-challenge` du vhost |
| Session admin perdue après mise à jour | la clé de signature vit dans `runtime/data/.secret_key` — vérifier sa présence (0600) |

## 11. Contrôles de recette

```bash
.venv/bin/python -m pytest tests/ -q                   # suite complète (Python)
HUB_BASE_URL=http://127.0.0.1:13744 .venv/bin/python tests/browser/acceptance.py
HUB_SCOPE=public HUB_BASE_URL=http://127.0.0.1:13744 .venv/bin/python tests/browser/acceptance.py
```

La recette navigateur exige Playwright + Chromium (`requirements-dev.txt`) ; sur
un poste neuf : `playwright install chromium`. Variables : `HUB_SCOPE`
(`full` / `public`), `HUB_ADMIN_PASSWORD` (compte existant), `HUB_SKIP_CERT`
(instance locale sans helper), `HUB_SHOTS_DIR` (captures de validation).
