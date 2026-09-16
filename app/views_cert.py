"""Administration du certificat TLS de Hub (via le helper root).

Parcours en deux temps :
1. **Valider** : la paire (certificat, clé, chaîne) est envoyée au helper qui
   effectue toutes les vérifications et renvoie les métadonnées + un ticket à
   usage unique lié à la session (10 minutes) ;
2. **Activer** : le helper revalide, bascule la paire atomiquement, teste et
   recharge Nginx, vérifie le certificat réellement servi — et restaure la paire
   précédente en cas d'échec.

Deux méthodes d'import alimentent ce même pipeline :
- **PKCS#12 / PFX** (recommandé) : un seul fichier, éventuellement protégé par un
  mot de passe, dont on extrait le certificat feuille, la clé privée et la chaîne
  — le tout en mémoire, mot de passe éphémère jamais conservé ;
- **PEM / CRT avancé** : certificat, clé privée et chaîne séparés (DER accepté).
"""

from __future__ import annotations

import hashlib
import json

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for

from . import auth, certclient, certparse, db
from .security import origin_ok

bp = Blueprint("cert", __name__, url_prefix="/admin/certificates")


def _trusted():
    return current_app.extensions["hub_trusted_proxies"]


def _require_csrf(session_row: dict) -> None:
    if not origin_ok(request, _trusted()) or not auth.csrf_ok(
        session_row, request.form.get("_csrf")
    ):
        abort(403)


def _render_page(session_row: dict, *, validation=None, status_code: int = 200):
    status, helper_error = None, None
    try:
        status = certclient.get_status()
    except certclient.CertHelperError as error:
        helper_error = str(error)
    return (
        render_template(
            "admin/certificates.html",
            csrf=session_row["csrf_token"],
            admin_username=session_row["username"],
            active_page="certificates",
            status=status,
            helper_error=helper_error,
            validation=validation,
        ),
        status_code,
    )


def _finish_validation(
    session_row: dict, certificate: bytes, private_key: bytes, chain: bytes, *, source: str
):
    """Pipeline commun : validation par le helper, ticket à usage unique, résumé."""
    try:
        result = certclient.validate_certificate(certificate, private_key, chain)
    except certclient.CertHelperError as error:
        flash(f"Validation refusée : {error}", "error")
        return redirect(url_for("cert.certificates"))

    ticket = result.get("ticket", "")
    connection = auth.db_connection()
    connection.execute(
        "DELETE FROM cert_validations WHERE session_hash = ? OR expires_at <= ?",
        (session_row["token_hash"], db.now_iso()),
    )
    connection.execute(
        "INSERT INTO cert_validations (ticket_hash, session_hash, summary, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            hashlib.sha256(ticket.encode("ascii")).hexdigest(),
            session_row["token_hash"],
            _serialize_summary(result),
            db.now_iso(),
            result.get("expiresAt", db.now_iso()),
        ),
    )
    connection.commit()
    current_app.logger.info(
        "Certificat : paire validée (import %s, en attente d'activation)", source
    )
    return _render_page(
        session_row,
        validation={
            "summary": result.get("summary", {}),
            "ticket": ticket,
            "expiresAt": result.get("expiresAt"),
            "source": source,
        },
    )


@bp.get("")
@auth.admin_required
def certificates():
    session_row = auth.require_session()
    return _render_page(session_row)


@bp.post("/validate")
@auth.admin_required
def validate():
    session_row = auth.require_session()
    _require_csrf(session_row)
    max_bytes = current_app.config["CERT_MAX_BYTES"]

    def read_file(field: str, *, required: bool) -> bytes | None:
        storage = request.files.get(field)
        if storage is None or not storage.filename:
            if required:
                flash(f"Le fichier « {field} » est requis.", "error")
                return None
            return b""
        data = storage.read(max_bytes + 1)
        if not data:
            flash(f"Le fichier « {field} » est vide.", "error")
            return None
        if len(data) > max_bytes:
            flash(
                f"Le fichier « {field} » est trop volumineux "
                f"({max_bytes // 1024} Ko maximum).",
                "error",
            )
            return None
        return data

    certificate = read_file("certificate", required=True)
    if certificate is None:
        return redirect(url_for("cert.certificates"))
    private_key = read_file("private_key", required=True)
    if private_key is None:
        return redirect(url_for("cert.certificates"))
    chain = read_file("chain", required=False)
    if chain is None:
        return redirect(url_for("cert.certificates"))

    try:
        certificate = certparse.normalize_certificate(certificate)
        private_key = certparse.normalize_private_key(private_key)
    except certparse.CertificateInputError as error:
        current_app.logger.info("Certificat : import PEM refusé (%s)", error.code)
        flash(str(error), "error")
        return redirect(url_for("cert.certificates"))
    return _finish_validation(session_row, certificate, private_key, chain, source="PEM")


@bp.post("/validate-pkcs12")
@auth.admin_required
def validate_pkcs12():
    """Import PKCS#12 / PFX : extraction en mémoire puis pipeline commun."""
    session_row = auth.require_session()
    _require_csrf(session_row)
    max_bytes = current_app.config["CERT_BUNDLE_MAX_BYTES"]
    data = b""
    password = ""
    storage = request.files.get("bundle")
    if storage is None or not storage.filename:
        flash("Le fichier PKCS#12 (.p12 / .pfx) est requis.", "error")
        return redirect(url_for("cert.certificates"))
    try:
        data = storage.read(max_bytes + 1)
        password = request.form.get("password") or ""
        if not data:
            raise certparse.CertificateInputError("Le fichier est vide.", "empty")
        if len(data) > max_bytes:
            raise certparse.CertificateInputError(
                f"Fichier trop volumineux ({max_bytes // 1024} Ko maximum).", "too_large"
            )
        certificate, private_key, chain = certparse.extract_pkcs12(data, password)
    except certparse.CertificateInputError as error:
        # Ni le mot de passe ni le contenu du bundle n'apparaissent ici.
        current_app.logger.info("Certificat : import PKCS#12 refusé (%s)", error.code)
        flash(str(error), "error")
        return redirect(url_for("cert.certificates"))
    finally:
        # Le secret est abandonné immédiatement : aucune trace durable.
        del data, password
    return _finish_validation(session_row, certificate, private_key, chain, source="PKCS#12")


def _serialize_summary(result: dict) -> str:
    return json.dumps(result.get("summary", {}), ensure_ascii=False)


@bp.post("/activate")
@auth.admin_required
def activate():
    session_row = auth.require_session()
    _require_csrf(session_row)
    ticket = (request.form.get("ticket") or "").strip()
    if not ticket:
        flash("Ticket de validation manquant ; relancez la validation.", "error")
        return redirect(url_for("cert.certificates"))
    ticket_hash = hashlib.sha256(ticket.encode("ascii")).hexdigest()
    connection = auth.db_connection()
    row = connection.execute(
        "SELECT expires_at FROM cert_validations WHERE ticket_hash = ? AND session_hash = ?",
        (ticket_hash, session_row["token_hash"]),
    ).fetchone()
    if row is None:
        flash("Validation introuvable pour cette session ; relancez la validation.", "error")
        return redirect(url_for("cert.certificates"))
    if row["expires_at"] <= db.now_iso():
        connection.execute("DELETE FROM cert_validations WHERE ticket_hash = ?", (ticket_hash,))
        connection.commit()
        flash("Validation expirée ; relancez la validation.", "error")
        return redirect(url_for("cert.certificates"))
    try:
        result = certclient.activate_certificate(ticket)
    except certclient.CertHelperError as error:
        flash(f"Activation refusée : {error}", "error")
        current_app.logger.warning("Certificat : activation refusée par le helper")
    else:
        summary = result.get("summary", {})
        current_app.logger.info(
            "Certificat : activation réussie (expire le %s)", summary.get("notAfter", "?")
        )
        flash(
            "Certificat activé : Nginx a été testé, rechargé et le certificat servi a été vérifié.",
            "success",
        )
    finally:
        connection.execute("DELETE FROM cert_validations WHERE ticket_hash = ?", (ticket_hash,))
        connection.commit()
    return redirect(url_for("cert.certificates"))
