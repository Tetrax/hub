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
# au moment de l'installation (deploy/install-helper.sh) : une seule source.

# Le conteneur tourne en lecture seule (compose) ; seuls /data et /tmp sont inscriptibles.
RUN mkdir -p /data/uploads

EXPOSE 8000
USER 1000:1000

CMD ["gunicorn", "--config", "app/gunicorn.conf.py", "app:create_app()"]
