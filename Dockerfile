# syntax=docker/dockerfile:1
# Image SNS Hub — build depuis la racine du dépôt canonique (contexte `.`).
# Le SHA Git est injecté par scripts/build.sh (labels OCI + variable lue par l'admin).
FROM python:3.12-slim@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217

ARG HUB_GIT_SHA=unknown

LABEL org.opencontainers.image.title="SNS Hub"
LABEL org.opencontainers.image.source="https://github.com/Tetrax/hub"
LABEL org.opencontainers.image.revision="${HUB_GIT_SHA}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HUB_GIT_SHA="${HUB_GIT_SHA}"

WORKDIR /opt/hub

COPY requirements.txt ./
RUN python -m pip install --requirement requirements.txt

COPY app ./app
COPY seeds ./seeds
# Le protocole du helper (app/hub_cert_protocol.py) est copié côté helper root
# au moment de l'installation (scripts/install-helper.sh) : une seule source.
#
# Le module d'activation/validation des certificats (helper/hub_certctl.py) est
# copié à la racine de l'image : le backend « proxy » du déploiement standalone
# réutilise EXACTEMENT les mêmes règles et les mêmes primitives atomiques que le
# helper root — aucune seconde implémentation. Il nécessite la CLI openssl (présente
# dans Debian slim uniquement si installée explicitement).
RUN apt-get update \
 && apt-get install --yes --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
COPY helper/hub_certctl.py ./hub_certctl.py

# Le conteneur tourne en lecture seule (compose) ; seuls /data et /tmp sont inscriptibles.
# Les sources doivent rester lisibles par l'utilisateur applicatif (uid 1000).
# /data (et /certs pour le mode standalone) appartiennent à l'utilisateur applicatif :
# un volume Docker nommé est initialisé depuis l'image, donc avec ces droits — aucune
# commande chown/mkdir n'est nécessaire sur l'hôte.
RUN mkdir -p /data/uploads /certs \
 && chown 1000:1000 /data /data/uploads /certs \
 && chmod 0644 /opt/hub/hub_certctl.py \
 && chmod 0755 /opt/hub/app/standalone/entrypoint.sh \
 && chmod -R a+rX /opt/hub/app /opt/hub/seeds

EXPOSE 8000 8443
USER 1000:1000

# L'entrypoint est transparent en mode HTTP (VPS, proxy externe : il exécute
# simplement la commande). En standalone (HUB_TLS_CERT défini), il crée le
# certificat temporaire de bootstrap avant de lancer le serveur HTTPS.
ENTRYPOINT ["/opt/hub/app/standalone/entrypoint.sh"]
CMD ["gunicorn", "--config", "app/gunicorn.conf.py", "app:create_app()"]
