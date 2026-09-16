"""Protocole du helper certificat Hub (socket Unix, JSON préfixé longueur).

Une seule implémentation pour les deux côtés :
- l'application (cliente) : `request_helper(...)` ;
- le helper root (serveur) : `receive_message` / `send_message`.

Stdlib uniquement (le helper tourne avec le python3 système, sans venv).
"""

from __future__ import annotations

import json
import socket
import struct
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = 1
HEADER = struct.Struct("!I")
MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
DEFAULT_TIMEOUT_SECONDS = 30.0
ACTIVATION_TIMEOUT_SECONDS = 90.0


class ProtocolError(ValueError):
    """Message mal formé ou hors limites."""


class HelperUnavailable(ConnectionError):
    """Socket injoignable ou réponse interrompue."""


class HelperError(RuntimeError):
    """Le helper a refusé l'opération (message utilisateur dans `str(error)`)."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("Clé JSON dupliquée.")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    raise ProtocolError("Constante JSON non autorisée.")


def encode_message(message: dict, *, maximum_bytes: int) -> bytes:
    payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > maximum_bytes:
        raise ProtocolError("Message trop volumineux.")
    return HEADER.pack(len(payload)) + payload


def decode_message(payload: bytes, *, maximum_bytes: int) -> dict:
    if len(payload) > maximum_bytes:
        raise ProtocolError("Message trop volumineux.")
    try:
        message = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise ProtocolError("Message JSON invalide.") from error
    if not isinstance(message, dict):
        raise ProtocolError("Le message doit être un objet JSON.")
    return message


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise ProtocolError("Connexion interrompue avant réception complète.")
        chunks.extend(chunk)
    return bytes(chunks)


def receive_message(connection: socket.socket, *, maximum_bytes: int) -> dict:
    header = _receive_exact(connection, HEADER.size)
    (length,) = HEADER.unpack(header)
    if length > maximum_bytes:
        raise ProtocolError("Message trop volumineux.")
    payload = _receive_exact(connection, length)
    return decode_message(payload, maximum_bytes=maximum_bytes)


def send_message(connection: socket.socket, message: dict, *, maximum_bytes: int) -> None:
    connection.sendall(encode_message(message, maximum_bytes=maximum_bytes))


def request_helper(
    socket_path: Path | str,
    message: dict,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    response_timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    """Envoie une requête au helper et retourne sa réponse brute.

    Lève `HelperUnavailable` si la socket est injoignable ou muette.
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout_seconds)
            connection.connect(str(socket_path))
            send_message(connection, message, maximum_bytes=MAX_REQUEST_BYTES)
            connection.settimeout(response_timeout_seconds)
            return receive_message(connection, maximum_bytes=MAX_RESPONSE_BYTES)
    except (OSError, socket.timeout) as error:
        raise HelperUnavailable(
            "Helper certificat injoignable (socket ou service indisponible)."
        ) from error
