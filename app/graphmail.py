"""Transport Microsoft 365 — envoi via Microsoft Graph (client credentials OAuth2).

Endpoints **figés** (aucune saisie administrateur ne peut les remplacer) :

- jeton : ``https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token``
  (grant ``client_credentials``, périmètre ``https://graph.microsoft.com/.default``) ;
- envoi : ``POST https://graph.microsoft.com/v1.0/users/{mailbox}/sendMail``,
  corps JSON (``body.contentType`` / ``body.content``) — jamais un message MIME
  pré-encodé. HTTP 202 = accepté (livraison finale non confirmée).

Aucune valeur sensible n'est journalisée ni rendue : ni secret client, ni jeton,
ni corps de réponse brut. Les erreurs sont traduites en messages opérateur ;
seul détail issu du fournisseur conservé est une classification AADSTS en liste
blanche. Les tests remplacent ``_urlopen`` (aucun appel réseau réel).
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

TOKEN_ENDPOINT = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
SENDMAIL_ENDPOINT = "https://graph.microsoft.com/v1.0/users/{mailbox}/sendMail"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

_AADSTS_HINTS = {
    "AADSTS90002": "Tenant Microsoft 365 introuvable.",
    "AADSTS700016": "Application Microsoft 365 introuvable dans ce tenant.",
    "AADSTS7000215": "Secret client Microsoft 365 refusé.",
    "AADSTS7000222": "Secret client Microsoft 365 expiré.",
    "AADSTS70011": "Périmètre Microsoft Graph invalide.",
}
_AADSTS_RE = re.compile(r"AADSTS\d{4,6}")

_urlopen = urllib.request.urlopen  # remplacé par les tests


def _log(stage: str, ok: bool, code: str, status: int | None = None) -> None:
    """Trace opérationnelle : jamais de jeton, de secret ni de corps de réponse."""
    safe_code = code if re.fullmatch(r"[a-z0-9_]{1,80}", code or "") else "normalized_error"
    logger.info(
        "Email Microsoft 365 : stage=%s success=%s code=%s status=%s",
        stage,
        "true" if ok else "false",
        safe_code,
        status if isinstance(status, int) else "none",
    )


def _aadsts_hint(error: urllib.error.HTTPError) -> str:
    """Classification AADSTS en liste blanche, extraite du corps d'erreur jeton."""
    try:
        payload = json.loads(error.read(16 * 1024).decode("utf-8", errors="replace"))
    except (OSError, ValueError, UnicodeError):
        return ""
    candidates: list[str] = []
    if isinstance(payload, dict):
        codes = payload.get("error_codes")
        if isinstance(codes, list):
            candidates.extend(f"AADSTS{code}" for code in codes if isinstance(code, int))
        description = payload.get("error_description")
        if isinstance(description, str):
            candidates.extend(_AADSTS_RE.findall(description))
    for candidate in candidates:
        hint = _AADSTS_HINTS.get(candidate)
        if hint:
            return hint
    return ""


def _token_error(status: int, hint: str) -> tuple[bool, str, str]:
    if hint:
        return False, hint, "microsoft365_token_invalid"
    if status in (400, 401):
        return (
            False,
            "Jeton Microsoft 365 refusé : vérifier le tenant, le client et le secret.",
            "microsoft365_token_invalid",
        )
    if status == 403:
        return False, "Authentification Microsoft 365 refusée.", "microsoft365_token_forbidden"
    if status == 429:
        return False, "Microsoft 365 limite temporairement les requêtes.", "microsoft365_throttled"
    if status >= 500:
        return False, "Microsoft 365 est temporairement indisponible.", "microsoft365_server_error"
    return False, "Authentification Microsoft 365 impossible.", "microsoft365_token_error"


def _delivery_error(status: int) -> tuple[bool, str, str]:
    if status == 401:
        return False, "Jeton Microsoft Graph non autorisé.", "microsoft365_unauthorized"
    if status == 403:
        return (
            False,
            "Permission Microsoft 365 refusée pour cette boîte (Mail.Send manquante ?).",
            "microsoft365_forbidden",
        )
    if status == 404:
        return False, "Boîte expéditrice Microsoft 365 introuvable.", "microsoft365_mailbox_not_found"
    if status == 429:
        return False, "Microsoft Graph limite temporairement les envois.", "microsoft365_throttled"
    if status >= 500:
        return False, "Microsoft Graph est temporairement indisponible.", "microsoft365_server_error"
    return False, "Envoi Microsoft Graph refusé.", "microsoft365_request_rejected"


def _exception_result(error: BaseException, *, stage: str) -> tuple[bool, str, str]:
    if isinstance(error, urllib.error.HTTPError):
        if stage == "token":
            return _token_error(error.code, _aadsts_hint(error))
        return _delivery_error(error.code)
    if isinstance(error, TimeoutError) or (
        isinstance(error, urllib.error.URLError) and isinstance(error.reason, TimeoutError)
    ):
        return (
            False,
            "Authentification Microsoft 365 expirée."
            if stage == "token"
            else "Connexion Microsoft Graph expirée.",
            "microsoft365_timeout",
        )
    if isinstance(error, (urllib.error.URLError, OSError)):
        return (
            False,
            "Connexion Microsoft Graph impossible.",
            "microsoft365_connection_error",
        )
    return (
        False,
        "Échec de l'authentification Microsoft 365."
        if stage == "token"
        else "Envoi Microsoft Graph impossible.",
        "microsoft365_token_error" if stage == "token" else "microsoft365_send_error",
    )


def _fetch_token(
    *, tenant_id: str, client_id: str, client_secret: str, timeout: int
) -> tuple[str, tuple[bool, str, str]]:
    endpoint = TOKEN_ENDPOINT.format(tenant=urllib.parse.quote(tenant_id, safe=""))
    request = urllib.request.Request(
        endpoint,
        data=urllib.parse.urlencode(
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": GRAPH_SCOPE,
                "grant_type": "client_credentials",
            }
        ).encode("ascii"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with _urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read(64 * 1024).decode("utf-8"))
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        OSError,
        TimeoutError,
        ValueError,
        UnicodeError,
    ) as error:
        result = _exception_result(error, stage="token")
        _log("token", False, result[2], getattr(error, "code", None))
        return "", result
    token = payload.get("access_token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        _log("token", False, "microsoft365_token_invalid")
        return "", (False, "Jeton Microsoft 365 invalide ou absent.", "microsoft365_token_invalid")
    _log("token", True, "ok")
    return token, (True, "", "")


def send(
    *,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    mailbox: str,
    recipients: tuple[str, ...],
    subject: str,
    text_body: str,
    html_body: str = "",
    timeout: int = 15,
) -> tuple[bool, str, str]:
    """Envoie un message ; retourne (ok, message opérateur, code normalisé).

    Ne lève jamais : une erreur imprévue est normalisée en échec propre — un
    transport email ne doit jamais interrompre la synchronisation Trivy.
    """
    try:
        return _send(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            mailbox=mailbox,
            recipients=recipients,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            timeout=timeout,
        )
    except Exception:  # filet de sécurité volontaire (jamais de détail, jamais de secret)
        logger.warning("Email Microsoft 365 : échec inattendu, erreur normalisée.")
        return False, "Envoi Microsoft Graph impossible.", "microsoft365_send_error"


def _send(
    *,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    mailbox: str,
    recipients: tuple[str, ...],
    subject: str,
    text_body: str,
    html_body: str = "",
    timeout: int = 15,
) -> tuple[bool, str, str]:
    if not (tenant_id and client_id and client_secret and mailbox and recipients):
        return False, "Configuration Microsoft 365 incomplète.", "microsoft365_incomplete"
    token, token_result = _fetch_token(
        tenant_id=tenant_id, client_id=client_id, client_secret=client_secret, timeout=timeout
    )
    if not token:
        return token_result

    endpoint = SENDMAIL_ENDPOINT.format(mailbox=urllib.parse.quote(mailbox, safe=""))
    message: dict = {
        "subject": subject,
        "body": {
            "contentType": "HTML" if html_body else "Text",
            "content": html_body or text_body,
        },
        "toRecipients": [
            {"emailAddress": {"address": address}} for address in recipients
        ],
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps({"message": message}, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with _urlopen(request, timeout=timeout) as response:
            status = response.getcode()
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        OSError,
        TimeoutError,
        ValueError,
        UnicodeError,
    ) as error:
        result = _exception_result(error, stage="delivery")
        _log("delivery", False, result[2], getattr(error, "code", None))
        return result
    if status != 202:
        result = _delivery_error(status)
        _log("delivery", False, result[2], status)
        return result
    _log("delivery", True, "ok", status)
    return True, "Email accepté par Microsoft Graph (HTTP 202 ; livraison non confirmée).", "ok"
