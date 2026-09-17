"""SNS Hub — application Flask.

Point d'entrée : `create_app()` (gunicorn : `app:create_app()`).
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from . import auth, db
from .config import DEFAULT_BRAND_LABEL, ensure_data_dirs, ensure_secret_key, load_config
from .security import apply_security_headers, is_https, parse_cidrs

__version__ = "1.5.0"


def create_app(config_overrides: dict | None = None) -> Flask:
    config = load_config(overrides=config_overrides)
    app = Flask(__name__)
    ensure_data_dirs(config)
    app.config.update(
        SECRET_KEY=ensure_secret_key(config),
        DATA_DIR=str(config["DATA_DIR"]),
        DB_PATH=str(config["DB_PATH"]),
        UPLOADS_DIR=str(config["UPLOADS_DIR"]),
        TLS_HOSTNAME=config["TLS_HOSTNAME"],
        CERT_HELPER_SOCKET=config["CERT_HELPER_SOCKET"],
        CERT_BACKEND=config["CERT_BACKEND"],
        CERTS_DIR=config["CERTS_DIR"],
        TLS_CERT_FILE=config["TLS_CERT_FILE"],
        TLS_KEY_FILE=config["TLS_KEY_FILE"],
        TLS_BIND_PORT=config["TLS_BIND_PORT"],
        GUNICORN_PIDFILE=config["GUNICORN_PIDFILE"],
        SESSION_TTL_SECONDS=config["SESSION_TTL_SECONDS"],
        BRAND_LABEL=config["BRAND_LABEL"],
        GIT_SHA=config["GIT_SHA"],
        PROJECT_URL=config["PROJECT_URL"],
        HUB_VERSION=__version__,
        MAX_CONTENT_LENGTH=config["MAX_CONTENT_LENGTH"],
        MAX_UPLOAD_BYTES=config["MAX_UPLOAD_BYTES"],
        CERT_MAX_BYTES=config["CERT_MAX_BYTES"],
        CERT_BUNDLE_MAX_BYTES=config["CERT_BUNDLE_MAX_BYTES"],
        # Cookie de session Flask (jeton CSRF de pré-authentification) : mêmes
        # garde-fous que le cookie de session applicatif. `SECURE` est ajusté par
        # requête (avant_request) selon le schéma réellement détecté.
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,
        TEMPLATES_AUTO_RELOAD=False,
    )
    # Frontière proxy : seuls les CIDR explicitement déclarés sont de confiance ;
    # sans CIDR, les en-têtes X-Forwarded-* sont ignorés (voir app/security.py).
    app.extensions["hub_trusted_proxies"] = parse_cidrs(config["TRUSTED_PROXY_CIDRS"])
    db.init_db(app.config["DB_PATH"])
    app.teardown_appcontext(auth.close_db)

    from .views_admin import bp as admin_bp
    from .views_cert import bp as cert_bp
    from .views_public import bp as public_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(cert_bp)

    @app.before_request
    def _session_cookie_policy():
        # Le cookie de session Flask doit être `Secure` dès que la requête arrive
        # en HTTPS (directement, ou via un proxy déclaré dans la frontière de
        # confiance) — et rester utilisable en HTTP interne (VM sans proxy).
        app.config["SESSION_COOKIE_SECURE"] = is_https(
            request, app.extensions["hub_trusted_proxies"]
        )

    @app.after_request
    def _security_headers(response):
        return apply_security_headers(response, request, app.extensions["hub_trusted_proxies"])

    @app.context_processor
    def _inject_globals():
        from .urls import STATUS_LABELS

        return {
            "hub_version": __version__,
            "hub_git_sha": app.config.get("GIT_SHA"),
            "project_url": app.config.get("PROJECT_URL"),
            "tls_hostname": app.config.get("TLS_HOSTNAME") or None,
            "brand_label": app.config.get("BRAND_LABEL") or DEFAULT_BRAND_LABEL,
            "statuses": STATUS_LABELS,
        }

    @app.errorhandler(403)
    def _forbidden(_error):
        return (
            render_template("error.html", code=403, title="Accès refusé",
                            message="Cette action n'est pas autorisée."),
            403,
        )

    @app.errorhandler(404)
    def _not_found(_error):
        return (
            render_template("error.html", code=404, title="Page introuvable",
                            message="La page demandée n'existe pas ou plus."),
            404,
        )

    @app.errorhandler(413)
    def _too_large(_error):
        return (
            render_template(
                "error.html",
                code=413,
                title="Fichier trop volumineux",
                message="La requête dépasse la taille autorisée.",
            ),
            413,
        )

    @app.errorhandler(500)
    def _internal(_error):
        app.logger.exception("Erreur interne non gérée")
        return (
            render_template(
                "error.html",
                code=500,
                title="Erreur interne",
                message="Une erreur interne est survenue ; elle a été journalisée.",
            ),
            500,
        )

    return app
