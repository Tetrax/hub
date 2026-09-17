"""Transport Microsoft 365 (Graph) : payload, erreurs traduites, secrets protégés.

Aucun appel réseau réel : `graphmail._urlopen` est remplacé par un double qui
enregistre les requêtes et rejoue des réponses (ou des exceptions) scénarisées.
Les échanges HTTP sont vérifiés tels que Microsoft Graph les attend : jeton
client credentials sur `login.microsoftonline.com`, envoi JSON sur
`graph.microsoft.com/v1.0/users/{mailbox}/sendMail` (HTTP 202).
"""

from __future__ import annotations

import email.message
import io
import json
import logging
import urllib.error
import urllib.parse

import pytest

from app import graphmail

TENANT = "contoso.onmicrosoft.com"
CLIENT_ID = "11111111-2222-3333-4444-555555555555"
CLIENT_SECRET = "secret-client-a-ne-jamais-rendre"
MAILBOX = "hub@example.com"
TOKEN = "jeton-oauth-a-ne-jamais-journaliser"
RECIPIENTS = ("equipe@valdev.me", "soc@valdev.me")
SUBJECT = "[SNS Hub] Sécurité de l'image — 1 changement détecté"
TEXT = "SNS Hub — Sécurité de l'image\n"
HTML = "<html><body><p>é — ç</p></body></html>"


class FakeResponse:
    def __init__(self, status: int = 200, body: bytes = b""):
        self.status = status
        self._body = body

    def read(self, _limit: int | None = None) -> bytes:
        return self._body

    def getcode(self) -> int:
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    """Rejoue des réponses dans l'ordre ; enregistre chaque requête émise."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests: list = []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def token_response(token: str = TOKEN) -> FakeResponse:
    return FakeResponse(200, json.dumps({"access_token": token, "expires_in": 3599}).encode())


def http_error(status: int, body: dict | None = None) -> urllib.error.HTTPError:
    payload = json.dumps(body or {}).encode()
    return urllib.error.HTTPError(
        "https://login.microsoftonline.com",
        status,
        "erreur",
        email.message.Message(),
        io.BytesIO(payload),
    )


@pytest.fixture()
def opener(monkeypatch):
    def _install(*responses) -> FakeOpener:
        fake = FakeOpener(*responses)
        monkeypatch.setattr(graphmail, "_urlopen", fake)
        return fake

    return _install


def send(**overrides) -> tuple[bool, str, str]:
    arguments = {
        "tenant_id": TENANT,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "mailbox": MAILBOX,
        "recipients": RECIPIENTS,
        "subject": SUBJECT,
        "text_body": TEXT,
        "html_body": HTML,
        "timeout": 10,
    }
    arguments.update(overrides)
    return graphmail.send(**arguments)


# --- Chemin nominal ------------------------------------------------------------------


def test_a_successful_send_uses_the_fixed_endpoints_and_a_clean_payload(opener):
    fake = opener(token_response(), FakeResponse(202, b""))
    ok, message, code = send()
    assert ok, message
    assert "202" in message
    assert code == "ok"

    token_request = fake.requests[0]
    assert token_request.full_url == (
        f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    )
    assert token_request.get_method() == "POST"
    form = urllib.parse.parse_qs(token_request.data.decode("ascii"))
    assert form["grant_type"] == ["client_credentials"]
    assert form["client_id"] == [CLIENT_ID]
    assert form["client_secret"] == [CLIENT_SECRET]
    assert form["scope"] == ["https://graph.microsoft.com/.default"]

    mail_request = fake.requests[1]
    assert mail_request.full_url == (
        "https://graph.microsoft.com/v1.0/users/hub%40example.com/sendMail"
    )
    assert mail_request.get_method() == "POST"
    assert mail_request.get_header("Authorization") == f"Bearer {TOKEN}"
    payload = json.loads(mail_request.data.decode("utf-8"))
    message_payload = payload["message"]
    assert message_payload["subject"] == SUBJECT
    assert message_payload["body"]["contentType"] == "HTML"
    assert message_payload["body"]["content"] == HTML
    assert message_payload["toRecipients"] == [
        {"emailAddress": {"address": address}} for address in RECIPIENTS
    ]
    # L'adresse d'envoi n'est jamais imposée : la boîte Graph décide (ErrorSendAsDenied).
    assert "from" not in message_payload


def test_a_mailbox_guid_is_url_encoded(opener):
    fake = opener(token_response(), FakeResponse(202, b""))
    ok, _message, _code = send(mailbox=CLIENT_ID)
    assert ok
    assert fake.requests[1].full_url.endswith(f"/users/{CLIENT_ID}/sendMail")


def test_a_text_only_message_is_sent_as_text(opener):
    fake = opener(token_response(), FakeResponse(202, b""))
    ok, _message, _code = send(html_body="")
    assert ok
    payload = json.loads(fake.requests[1].data.decode("utf-8"))
    assert payload["message"]["body"]["contentType"] == "Text"
    assert payload["message"]["body"]["content"] == TEXT


def test_an_incomplete_configuration_refuses_before_any_connection(opener):
    fake = opener()
    ok, message, code = send(mailbox="")
    assert not ok and code == "microsoft365_incomplete"
    assert "incomplète" in message
    assert fake.requests == []


# --- Erreurs de jeton ----------------------------------------------------------------


def test_an_invalid_token_request_names_the_configuration(opener):
    opener(http_error(400))
    ok, message, code = send()
    assert not ok and code == "microsoft365_token_invalid"
    assert "tenant" in message and "client" in message and "secret" in message


def test_an_aadsts_hint_is_translated_from_a_whitelist(opener):
    opener(http_error(400, {"error_codes": [7000215], "error_description": "AADSTS7000215: bad"}))
    ok, message, _code = send()
    assert not ok and message == "Secret client Microsoft 365 refusé."

    opener(http_error(400, {"error_codes": [90002]}))
    ok, message, _code = send()
    assert not ok and message == "Tenant Microsoft 365 introuvable."


def test_an_unknown_aadsts_code_never_leaks_provider_text(opener):
    opener(http_error(400, {"error_description": "AADSTS999999: secret leaké ici"}))
    ok, message, _code = send()
    assert not ok
    assert "secret leaké" not in message
    assert message == "Jeton Microsoft 365 refusé : vérifier le tenant, le client et le secret."


def test_a_forbidden_token_request_is_a_clean_error(opener):
    opener(http_error(403))
    ok, message, code = send()
    assert not ok and code == "microsoft365_token_forbidden"
    assert message == "Authentification Microsoft 365 refusée."


def test_a_missing_token_in_the_response_is_refused(opener):
    opener(FakeResponse(200, b"{}"))
    ok, message, code = send()
    assert not ok and code == "microsoft365_token_invalid"
    assert "invalide" in message


# --- Erreurs d'envoi -----------------------------------------------------------------


@pytest.mark.parametrize(
    "status,needle",
    [
        (401, "Jeton Microsoft Graph non autorisé"),
        (403, "Mail.Send"),
        (404, "introuvable"),
        (429, "limite temporairement"),
        (500, "indisponible"),
        (400, "refusé"),
    ],
)
def test_delivery_errors_are_translated(opener, status, needle):
    opener(token_response(), http_error(status))
    ok, message, _code = send()
    assert not ok and needle in message


def test_a_non_202_status_is_not_a_success(opener):
    opener(token_response(), FakeResponse(200, b""))
    ok, message, _code = send()
    assert not ok and "refusé" in message


# --- Pannes réseau -------------------------------------------------------------------


def test_a_token_timeout_is_a_clean_error(opener):
    opener(TimeoutError("trop lent"))
    ok, message, code = send()
    assert not ok and code == "microsoft365_timeout"
    assert "expirée" in message


def test_a_delivery_timeout_is_a_clean_error(opener):
    opener(token_response(), TimeoutError("trop lent"))
    ok, message, code = send()
    assert not ok and code == "microsoft365_timeout"
    assert "expirée" in message


def test_a_connection_failure_is_a_clean_error(opener):
    opener(urllib.error.URLError("injoignable"))
    ok, message, code = send()
    assert not ok and code == "microsoft365_connection_error"
    assert "impossible" in message


def test_an_unexpected_failure_is_normalized_without_detail(opener):
    class Boom(Exception):
        pass

    opener(Boom(f"panne imprévue : {CLIENT_SECRET}"))
    ok, message, code = send()
    assert not ok and code == "microsoft365_send_error"
    assert message == "Envoi Microsoft Graph impossible."
    assert CLIENT_SECRET not in message


# --- Secrets et journaux --------------------------------------------------------------


def test_no_secret_or_token_ever_appears_in_a_result_or_a_log(opener, caplog):
    caplog.set_level(logging.DEBUG)
    opener(http_error(401))
    ok, message, _code = send()
    assert not ok
    assert CLIENT_SECRET not in message and TOKEN not in message
    for record in caplog.records:
        text = record.getMessage()
        assert CLIENT_SECRET not in text
        assert TOKEN not in text
        assert "Bearer" not in text

    opener(token_response(), http_error(500))
    ok, message, _code = send()
    assert not ok
    assert CLIENT_SECRET not in message and TOKEN not in message
    for record in caplog.records:
        assert CLIENT_SECRET not in record.getMessage()
        assert TOKEN not in record.getMessage()
