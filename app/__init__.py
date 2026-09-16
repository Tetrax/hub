"""SNS Hub — application Flask.

Point d'entrée : `create_app()` (gunicorn : `app:create_app()`).
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from . import auth, db
from .config import ensure_data_dirs, ensure_secret_key, load_config
from .security import apply_security_headers, parse_cidrs

__version__ = "1.0.0"


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
        SESSION_TTL_SECONDS=config["SESSION_TTL_SECONDS"],
        GIT_SHA=config["GIT_SHA"],
        PROJECT_URL=config["PROJECT_URL"],
        HUB_VERSION=__version__,
        MAX_CONTENT_LENGTH=config["MAX_CONTENT_LENGTH"],
        MAX_UPLOAD_BYTES=config["MAX_UPLOAD_BYTES"],
        CERT_MAX_BYTES=config["CERT_MAX_BYTES"],
        TEMPLATES_AUTO_RELOAD=False,
    )
    app.extensions["hub_trusted_proxies"] = parse_cidrs(config["TRUSTED_PROXY_CIDRS"])
    db.init_db(app.config["DB_PATH"])
    app.teardown_appcontext(auth.close_db)

    from .views_admin import bp as admin_bp
    from .views_cert import bp as cert_bp
    from .views_public import bp as public_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(cert_bp)

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
