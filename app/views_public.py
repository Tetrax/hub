"""Routes publiques : landing page du catalogue, images, santé."""

from __future__ import annotations

from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)

from . import auth, catalog, db, uploads

bp = Blueprint("public", __name__)


@bp.get("/")
def index():
    connection = auth.db_connection()
    category = (request.args.get("category") or "").strip() or None
    query = (request.args.get("q") or "").strip() or None
    apps = catalog.list_apps(connection, enabled_only=True, category_slug=category, query=query)
    categories = catalog.public_categories(connection)
    open_new_tab = db.get_setting(connection, "open_links_new_tab", "1") == "1"
    response = make_response(
        render_template(
            "index.html",
            apps=apps,
            categories=categories,
            active_category=category,
            query=query or "",
            open_new_tab=open_new_tab,
        )
    )
    response.headers["Cache-Control"] = "no-cache"
    return response


@bp.get("/img/<filename>")
def uploaded_image(filename: str):
    if not uploads.is_valid_image_name(filename):
        abort(404)
    return send_from_directory(
        current_app.config["UPLOADS_DIR"], filename, max_age=7 * 24 * 3600, conditional=True
    )


@bp.get("/healthz")
def healthz():
    try:
        auth.db_connection().execute("SELECT 1").fetchone()
    except Exception:  # noqa: BLE001 — le healthcheck doit répondre, pas lever
        current_app.logger.exception("Healthcheck : base inaccessible")
        return jsonify(status="error"), 503
    return jsonify(
        status="ok",
        version=current_app.config["HUB_VERSION"],
        git_sha=current_app.config.get("GIT_SHA"),
    )


@bp.get("/favicon.ico")
def favicon():
    return redirect(url_for("static", filename="img/favicon.svg"), code=302)
