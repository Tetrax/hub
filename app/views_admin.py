"""Administration : tableau de bord, CRUD du catalogue, paramètres, compte."""

from __future__ import annotations

import secrets
from pathlib import Path

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session as flask_session,
    url_for,
)

from . import auth, catalog, db, uploads
from .security import client_ip, origin_ok
from .urls import (
    STATUS_LABELS,
    slugify,
    validate_app_url,
    validate_description,
    validate_name,
    validate_slug,
    validate_status,
)

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _trusted():
    return current_app.extensions["hub_trusted_proxies"]


def _require_csrf(session_row: dict) -> None:
    if not origin_ok(request, _trusted()) or not auth.csrf_ok(
        session_row, request.form.get("_csrf")
    ):
        abort(403)


def render_admin(template: str, session_row: dict, **context):
    context.setdefault("csrf", session_row["csrf_token"])
    context.setdefault("admin_username", session_row["username"])
    context.setdefault("is_principal", auth.is_principal(session_row))
    return render_template(template, **context)


def _preauth_csrf() -> str:
    token = flask_session.get("preauth_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        flask_session["preauth_csrf"] = token
    return token


def _preauth_csrf_ok() -> bool:
    expected = flask_session.get("preauth_csrf")
    submitted = request.form.get("_csrf")
    return bool(expected and submitted and secrets.compare_digest(expected, submitted))


# --- Tableau de bord ---------------------------------------------------------


@bp.get("/")
@auth.admin_required
def dashboard():
    session_row = auth.require_session()
    connection = auth.db_connection()
    stats = catalog.stats(connection)
    # L'état du certificat est une configuration sensible : administrateur
    # principal uniquement (le modérateur n'y a aucun accès).
    cert_status, cert_error = None, None
    if auth.is_principal(session_row):
        from . import certclient

        try:
            cert_status = certclient.get_status()
        except certclient.CertHelperError as error:
            cert_error = str(error)
    return render_admin(
        "admin/dashboard.html",
        session_row,
        active_page="dashboard",
        stats=stats,
        cert_status=cert_status,
        cert_error=cert_error,
    )


# --- Première configuration / login / logout ---------------------------------


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    connection = auth.db_connection()
    if auth.has_admin(connection):
        return redirect(url_for("admin.login"))
    if request.method == "POST":
        if not origin_ok(request, _trusted()) or not _preauth_csrf_ok():
            abort(403)
        username = (request.form.get("username") or "").strip() or "admin"
        password = request.form.get("password") or ""
        confirmation = request.form.get("confirmation") or ""
        error = None
        username_ok, error = auth.validate_username(username)
        if username_ok:
            password_ok, password_error = auth.validate_password(password)
            if not password_ok:
                error = password_error
            elif password != confirmation:
                error = "Les deux mots de passe ne correspondent pas."
        if error is not None:
            flash(error, "error")
            return render_template("admin/setup.html", csrf=_preauth_csrf(), username=username)
        if not auth.create_admin(connection, username, password):
            flash("Un compte administrateur existe déjà.", "error")
            return redirect(url_for("admin.login"))
        token, _ = auth.create_session(connection, 1, username)
        response = redirect(url_for("admin.dashboard"))
        auth.set_session_cookie(response, token)
        flash("Compte administrateur créé.", "success")
        return response
    return render_template("admin/setup.html", csrf=_preauth_csrf(), username="admin")


@bp.route("/login", methods=["GET", "POST"])
def login():
    connection = auth.db_connection()
    if not auth.has_admin(connection):
        return redirect(url_for("admin.setup"))
    if request.method == "POST":
        if not origin_ok(request, _trusted()) or not _preauth_csrf_ok():
            abort(403)
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        ip = client_ip(request, _trusted())
        remaining = auth.lock_remaining(connection, username, ip)
        if remaining > 0:
            minutes = max(1, remaining // 60 + 1)
            flash(f"Trop de tentatives échouées. Nouvelle tentative possible dans {minutes} min.", "error")
            return render_template("admin/login.html", csrf=_preauth_csrf()), 429
        # La vérification et l'insertion de session partagent le verrou SQLite :
        # un reset/désactivation ne peut s'intercaler et laisser un ancien login
        # créer une nouvelle session après la révocation.
        connection.execute("BEGIN IMMEDIATE")
        account = auth.authenticate(connection, username, password)
        if account is not None:
            token, _ = auth.create_session(connection, account["id"], account["username"])
            auth.clear_failures(connection, username, ip)
            auth.purge_expired_sessions(connection)
            response = redirect(url_for("admin.dashboard"))
            auth.set_session_cookie(response, token)
            return response
        connection.rollback()
        auth.register_failure(connection, username, ip)
        current_app.logger.warning("Échec de connexion administrateur (identifiant refusé)")
        flash("Identifiants invalides.", "error")
    return render_template("admin/login.html", csrf=_preauth_csrf())


@bp.post("/logout")
@auth.admin_required
def logout():
    session_row = auth.require_session()
    _require_csrf(session_row)
    auth.destroy_session(auth.db_connection(), session_row["token"])
    response = redirect(url_for("admin.login"))
    auth.clear_session_cookie(response)
    return response


# --- CRUD du catalogue -------------------------------------------------------


def _parse_app_form(form) -> tuple[dict, list[str]]:
    data: dict = {}
    errors: list[str] = []
    name, error = validate_name(form.get("name"))
    if error:
        errors.append(error)
    else:
        data["name"] = name
    raw_slug = (form.get("slug") or "").strip()
    if raw_slug:
        slug, error = validate_slug(raw_slug)
    else:
        slug, error = slugify(data.get("name", "")), None
    if error:
        errors.append(error)
    else:
        data["slug"] = slug
    description, error = validate_description(form.get("description"))
    if error:
        errors.append(error)
    data["description"] = description
    url, error = validate_app_url(form.get("url"))
    if error:
        errors.append(error)
    else:
        data["url"] = url
    raw_category = (form.get("category_id") or "").strip()
    if raw_category.isdigit():
        data["category_id"] = int(raw_category)
    else:
        errors.append("Catégorie obligatoire : choisissez une catégorie existante.")
    status, error = validate_status(form.get("status"))
    if error:
        errors.append(error)
    else:
        data["status"] = status
    return data, errors


def _form_context(connection, session_row, app_row, form):
    def value(field: str, default: str = "") -> str:
        raw = form.get(field) if form else None
        if (raw is None or raw == "") and app_row is not None and field in app_row.keys():
            raw = app_row[field]
        return str(raw) if raw is not None else default

    fallback = catalog.get_fallback_category(connection)
    values = {
        "name": value("name"),
        "slug": value("slug"),
        "url": value("url"),
        "description": value("description"),
        "category_id": value("category_id", str(fallback["id"]) if fallback else ""),
        "status": value("status", "production"),
    }
    return {
        "csrf": session_row["csrf_token"],
        "admin_username": session_row["username"],
        "is_principal": auth.is_principal(session_row),
        "active_page": "apps",
        "app": app_row,
        "values": values,
        "remove_image_requested": bool(form.get("remove_image")) if form else False,
        "categories": catalog.list_categories(connection),
        "statuses": STATUS_LABELS,
    }


@bp.get("/apps")
@auth.admin_required
def apps_list():
    session_row = auth.require_session()
    connection = auth.db_connection()
    return render_admin(
        "admin/apps_list.html", session_row, active_page="apps", apps=catalog.list_apps(connection)
    )


@bp.route("/apps/new", methods=["GET", "POST"])
@auth.admin_required
def app_new():
    session_row = auth.require_session()
    connection = auth.db_connection()
    if request.method == "POST":
        _require_csrf(session_row)
        data, errors = _parse_app_form(request.form)
        if errors:
            for message in errors:
                flash(message, "error")
            return render_template(
                "admin/app_form.html", **_form_context(connection, session_row, None, request.form)
            )
        image_file = request.files.get("image")
        saved_image = None
        if image_file is not None and image_file.filename:
            saved_image, error = uploads.save_screenshot(
                image_file,
                Path(current_app.config["UPLOADS_DIR"]),
                current_app.config["MAX_UPLOAD_BYTES"],
            )
            if error:
                flash(error, "error")
                return render_template(
                    "admin/app_form.html",
                    **_form_context(connection, session_row, None, request.form),
                )
        data["image"] = saved_image
        app_id, error = catalog.create_app(connection, data)
        if error:
            uploads.delete_screenshot(Path(current_app.config["UPLOADS_DIR"]), saved_image)
            flash(error, "error")
            return render_template(
                "admin/app_form.html", **_form_context(connection, session_row, None, request.form)
            )
        current_app.logger.info("Catalogue : application créée (id=%s)", app_id)
        flash(f"Application « {data['name']} » créée.", "success")
        return redirect(url_for("admin.apps_list"))
    return render_template(
        "admin/app_form.html", **_form_context(connection, session_row, None, {})
    )


@bp.route("/apps/<int:app_id>/edit", methods=["GET", "POST"])
@auth.admin_required
def app_edit(app_id: int):
    session_row = auth.require_session()
    connection = auth.db_connection()
    app_row = catalog.get_app(connection, app_id)
    if app_row is None:
        abort(404)
    if request.method == "POST":
        _require_csrf(session_row)
        data, errors = _parse_app_form(request.form)
        if errors:
            for message in errors:
                flash(message, "error")
            return render_template(
                "admin/app_form.html",
                **_form_context(connection, session_row, app_row, request.form),
            )
        uploads_dir = Path(current_app.config["UPLOADS_DIR"])
        old_image = app_row["image"]
        new_image = None
        remove_image = request.form.get("remove_image") == "1"
        image_file = request.files.get("image")
        if image_file is not None and image_file.filename:
            new_image, error = uploads.save_screenshot(
                image_file, uploads_dir, current_app.config["MAX_UPLOAD_BYTES"]
            )
            if error:
                flash(error, "error")
                return render_template(
                    "admin/app_form.html",
                    **_form_context(connection, session_row, app_row, request.form),
                )
        updated, error = catalog.update_app(connection, app_id, data)
        if not updated:
            if new_image:
                uploads.delete_screenshot(uploads_dir, new_image)
            flash(error or "Application introuvable.", "error")
            return render_template(
                "admin/app_form.html",
                **_form_context(connection, session_row, app_row, request.form),
            )
        if new_image:
            catalog.set_image(connection, app_id, new_image)
            uploads.delete_screenshot(uploads_dir, old_image)
        elif remove_image and old_image:
            catalog.set_image(connection, app_id, None)
            uploads.delete_screenshot(uploads_dir, old_image)
        current_app.logger.info("Catalogue : application modifiée (id=%s)", app_id)
        flash(f"Application « {data['name']} » mise à jour.", "success")
        return redirect(url_for("admin.apps_list"))
    return render_template(
        "admin/app_form.html", **_form_context(connection, session_row, app_row, {})
    )


@bp.post("/apps/<int:app_id>/toggle")
@auth.admin_required
def app_toggle(app_id: int):
    session_row = auth.require_session()
    _require_csrf(session_row)
    connection = auth.db_connection()
    enabled = catalog.toggle_app(connection, app_id)
    if enabled is None:
        abort(404)
    flash(
        "Application affichée sur la landing page." if enabled else "Application masquée.",
        "success",
    )
    return redirect(url_for("admin.apps_list"))


@bp.post("/apps/<int:app_id>/move")
@auth.admin_required
def app_move(app_id: int):
    session_row = auth.require_session()
    _require_csrf(session_row)
    direction = request.form.get("direction", "")
    if direction not in {"up", "down"}:
        abort(400)
    catalog.move_app(auth.db_connection(), app_id, direction)
    return redirect(url_for("admin.apps_list"))


@bp.post("/apps/<int:app_id>/delete")
@auth.admin_required
def app_delete(app_id: int):
    session_row = auth.require_session()
    _require_csrf(session_row)
    if request.form.get("confirm_delete") != "1":
        flash("Suppression annulée : confirmation manquante.", "error")
        return redirect(url_for("admin.apps_list"))
    connection = auth.db_connection()
    app_row = catalog.get_app(connection, app_id)
    if app_row is None:
        abort(404)
    catalog.delete_app(connection, app_id)
    uploads.delete_screenshot(Path(current_app.config["UPLOADS_DIR"]), app_row["image"])
    current_app.logger.info("Catalogue : application supprimée (id=%s)", app_id)
    flash(f"Application « {app_row['name']} » supprimée.", "success")
    return redirect(url_for("admin.apps_list"))


# --- Catégories --------------------------------------------------------------


def _category_id_from_form(raw: str | None) -> int | None:
    value = (raw or "").strip()
    return int(value) if value.isdigit() else None


@bp.get("/categories")
@auth.admin_required
def categories_list():
    session_row = auth.require_session()
    connection = auth.db_connection()
    return render_admin(
        "admin/categories.html",
        session_row,
        active_page="categories",
        categories=catalog.list_categories(connection),
        fallback=catalog.get_fallback_category(connection),
    )


@bp.post("/categories/create")
@auth.admin_required
def category_create():
    session_row = auth.require_session()
    _require_csrf(session_row)
    connection = auth.db_connection()
    row, error = catalog.create_category(connection, request.form.get("name") or "")
    if error:
        flash(error, "error")
    elif row is not None:
        current_app.logger.info("Catégories : création « %s »", row["name"])
        flash(f"Catégorie « {row['name']} » créée.", "success")
    return redirect(url_for("admin.categories_list"))


@bp.post("/categories/<int:category_id>/rename")
@auth.admin_required
def category_rename(category_id: int):
    session_row = auth.require_session()
    _require_csrf(session_row)
    connection = auth.db_connection()
    ok, error = catalog.rename_category(connection, category_id, request.form.get("name") or "")
    if not ok:
        flash(error or "Renommage impossible.", "error")
    else:
        current_app.logger.info("Catégories : renommage (id=%s)", category_id)
        flash("Catégorie renommée.", "success")
    return redirect(url_for("admin.categories_list"))


@bp.post("/categories/<int:category_id>/move")
@auth.admin_required
def category_move(category_id: int):
    session_row = auth.require_session()
    _require_csrf(session_row)
    direction = request.form.get("direction", "")
    if direction not in {"up", "down"}:
        abort(400)
    catalog.move_category(auth.db_connection(), category_id, direction)
    return redirect(url_for("admin.categories_list"))


@bp.route("/categories/<int:category_id>/delete", methods=["GET", "POST"])
@auth.admin_required
def category_delete(category_id: int):
    session_row = auth.require_session()
    connection = auth.db_connection()
    category = catalog.get_category(connection, category_id)
    if category is None:
        abort(404)
    if category["is_fallback"]:
        flash("La catégorie de repli ne peut pas être supprimée.", "error")
        return redirect(url_for("admin.categories_list"))
    if request.method == "POST":
        _require_csrf(session_row)
        reassign_to = _category_id_from_form(request.form.get("reassign_to"))
        ok, error, reassigned = catalog.delete_category(connection, category_id, reassign_to)
        if not ok:
            flash(error or "Suppression impossible.", "error")
            return redirect(url_for("admin.categories_list"))
        current_app.logger.info(
            "Catégories : suppression (id=%s, applications réassignées=%s)", category_id, reassigned
        )
        if reassigned:
            flash(
                f"Catégorie « {category['name']} » supprimée ; {reassigned} application"
                f"{'s' if reassigned != 1 else ''} réassignée{'s' if reassigned != 1 else ''}.",
                "success",
            )
        else:
            flash(f"Catégorie « {category['name']} » supprimée.", "success")
        return redirect(url_for("admin.categories_list"))
    used_apps = catalog.apps_in_category(connection, category_id)
    return render_admin(
        "admin/category_delete.html",
        session_row,
        active_page="categories",
        category=category,
        apps=used_apps,
        targets=[row for row in catalog.list_categories(connection) if row["id"] != category_id],
        fallback=catalog.get_fallback_category(connection),
    )


@bp.post("/categories/quick-create")
@auth.admin_required
def category_quick_create():
    """Création rapide depuis le formulaire application (réponse JSON)."""
    session_row = auth.require_session()
    _require_csrf(session_row)
    connection = auth.db_connection()
    row, error = catalog.create_category(connection, request.form.get("name") or "")
    if error or row is None:
        return jsonify(ok=False, error=error or "Création impossible."), 400
    current_app.logger.info("Catégories : création rapide « %s »", row["name"])
    return jsonify(ok=True, category={"id": row["id"], "name": row["name"], "slug": row["slug"]})


# --- Paramètres et compte ----------------------------------------------------


@bp.get("/settings")
@auth.admin_required
def settings():
    session_row = auth.require_session()
    connection = auth.db_connection()
    row = auth.get_account(connection, session_row["user_id"])
    return render_admin(
        "admin/settings.html",
        session_row,
        active_page="settings",
        open_new_tab=db.get_setting(connection, "open_links_new_tab", "1") == "1",
        account_info=dict(row) if row else None,
    )


@bp.post("/settings/preferences")
@auth.principal_required
def settings_preferences():
    session_row = auth.require_session()
    _require_csrf(session_row)
    value = "1" if request.form.get("open_links_new_tab") == "1" else "0"
    db.set_setting(auth.db_connection(), "open_links_new_tab", value)
    flash("Préférences enregistrées.", "success")
    return redirect(url_for("admin.settings"))


@bp.post("/settings/password")
@auth.admin_required
def settings_password():
    session_row = auth.require_session()
    _require_csrf(session_row)
    connection = auth.db_connection()
    current = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    confirmation = request.form.get("confirmation") or ""
    ok, error = auth.validate_password(new_password)
    if not ok:
        flash(error, "error")
        return redirect(url_for("admin.settings"))
    if new_password != confirmation:
        flash("Les deux mots de passe ne correspondent pas.", "error")
        return redirect(url_for("admin.settings"))
    error = auth.change_own_password(connection, session_row, current, new_password)
    if error is not None:
        flash(error, "error")
        return redirect(url_for("admin.settings"))
    current_app.logger.info(
        "Administration : mot de passe modifié (compte id=%s), sessions du compte invalidées",
        session_row["user_id"],
    )
    response = redirect(url_for("admin.login"))
    auth.clear_session_cookie(response)
    flash("Mot de passe modifié. Veuillez vous reconnecter.", "success")
    return response


# --- Comptes modérateurs (administrateur principal) --------------------------


def _account_target(connection, user_id: int):
    """Compte ciblé par une action de gestion, ou 403/404.

    Le compte principal (et tout compte non modérateur) est intouchable par ces
    fonctions : ni désactivation, ni suppression, ni réinitialisation.
    """
    row = auth.get_account(connection, user_id)
    if row is None:
        abort(404)
    if int(row["id"]) == 1 or row["role"] != auth.ROLE_MODERATOR:
        abort(403)
    return row


@bp.get("/accounts")
@auth.principal_required
def accounts_list():
    session_row = auth.require_session()
    connection = auth.db_connection()
    accounts = auth.list_accounts(connection)
    return render_admin(
        "admin/accounts.html",
        session_row,
        active_page="accounts",
        accounts=accounts,
        moderators=[
            row
            for row in accounts
            if row["role"] == auth.ROLE_MODERATOR and int(row["id"]) != 1
        ],
    )


@bp.post("/accounts/create")
@auth.principal_required
def account_create():
    session_row = auth.require_session()
    _require_csrf(session_row)
    connection = auth.db_connection()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    confirmation = request.form.get("confirmation") or ""
    error = None
    ok, error = auth.validate_username(username)
    if ok:
        ok, password_error = auth.validate_password(password)
        if not ok:
            error = password_error
        elif password != confirmation:
            ok, error = False, "Les deux mots de passe ne correspondent pas."
    if ok:
        row, error = auth.create_moderator(connection, username, password)
        if row is not None:
            current_app.logger.info("Comptes : modérateur créé (id=%s)", row["id"])
            flash(f"Compte modérateur « {row['username']} » créé.", "success")
            return redirect(url_for("admin.accounts_list"))
    current_app.logger.info("Comptes : création de modérateur refusée")
    flash(error or "Création impossible.", "error")
    return redirect(url_for("admin.accounts_list"))


@bp.post("/accounts/<int:user_id>/deactivate")
@auth.principal_required
def account_deactivate(user_id: int):
    session_row = auth.require_session()
    _require_csrf(session_row)
    connection = auth.db_connection()
    row = _account_target(connection, user_id)
    auth.set_account_active(connection, user_id, False)
    current_app.logger.info("Comptes : modérateur désactivé (id=%s)", user_id)
    flash(f"Compte « {row['username']} » désactivé ; ses sessions sont révoquées.", "success")
    return redirect(url_for("admin.accounts_list"))


@bp.post("/accounts/<int:user_id>/reactivate")
@auth.principal_required
def account_reactivate(user_id: int):
    session_row = auth.require_session()
    _require_csrf(session_row)
    connection = auth.db_connection()
    row = _account_target(connection, user_id)
    auth.set_account_active(connection, user_id, True)
    current_app.logger.info("Comptes : modérateur réactivé (id=%s)", user_id)
    flash(f"Compte « {row['username']} » réactivé.", "success")
    return redirect(url_for("admin.accounts_list"))


@bp.post("/accounts/<int:user_id>/delete")
@auth.principal_required
def account_delete(user_id: int):
    session_row = auth.require_session()
    _require_csrf(session_row)
    connection = auth.db_connection()
    row = _account_target(connection, user_id)
    if request.form.get("confirm_delete") != "1":
        flash("Suppression annulée : confirmation manquante.", "error")
        return redirect(url_for("admin.accounts_list"))
    auth.delete_account(connection, user_id)
    current_app.logger.info("Comptes : modérateur supprimé (id=%s)", user_id)
    flash(f"Compte « {row['username']} » supprimé ; ses sessions sont révoquées.", "success")
    return redirect(url_for("admin.accounts_list"))


@bp.post("/accounts/reset-password")
@auth.principal_required
def account_reset_password():
    session_row = auth.require_session()
    _require_csrf(session_row)
    connection = auth.db_connection()
    raw_id = (request.form.get("account_id") or "").strip()
    if not raw_id.isdigit():
        abort(404)
    row = _account_target(connection, int(raw_id))
    new_password = request.form.get("new_password") or ""
    confirmation = request.form.get("confirmation") or ""
    ok, error = auth.validate_password(new_password)
    if ok and new_password != confirmation:
        ok, error = False, "Les deux mots de passe ne correspondent pas."
    if not ok:
        flash(error, "error")
        return redirect(url_for("admin.accounts_list"))
    auth.update_password(connection, int(row["id"]), new_password)
    auth.destroy_user_sessions(connection, int(row["id"]))
    current_app.logger.info("Comptes : mot de passe réinitialisé (id=%s)", row["id"])
    flash(
        f"Mot de passe du compte « {row['username']} » réinitialisé ; "
        "ses sessions sont révoquées.",
        "success",
    )
    return redirect(url_for("admin.accounts_list"))
