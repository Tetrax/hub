"""Protocole du helper : cadrage, limites, erreurs, client."""

from __future__ import annotations

import json
import socket
import struct
import threading

import pytest

import hub_cert_protocol as protocol


class _EchoServer(threading.Thread):
    """Serveur minimal : renvoie un message fixe après réception."""

    def __init__(self, socket_path, response: dict):
        super().__init__(daemon=True)
        self.socket_path = str(socket_path)
        self.response = response
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.socket_path)
        self._server.listen(2)
        self._stop = threading.Event()
        self.received: list[dict] = []

    def run(self) -> None:
        self._server.settimeout(1.0)
        while not self._stop.is_set():
            try:
                connection, _ = self._server.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with connection:
                try:
                    message = protocol.receive_message(
                        connection, maximum_bytes=protocol.MAX_REQUEST_BYTES
                    )
                    self.received.append(message)
                    protocol.send_message(
                        connection, self.response, maximum_bytes=protocol.MAX_RESPONSE_BYTES
                    )
                except Exception:  # noqa: BLE001
                    continue

    def stop(self) -> None:
        self._stop.set()
        try:
            self._server.close()
        except OSError:
            pass


def test_message_round_trip_via_socket(tmp_path):
    socket_path = tmp_path / "helper.sock"
    server = _EchoServer(socket_path, {"ok": True, "value": 42})
    server.start()
    try:
        response = protocol.request_helper(
            socket_path,
            {"version": 1, "action": "ping"},
            timeout_seconds=5,
            response_timeout_seconds=5,
        )
    finally:
        server.stop()
    assert response == {"ok": True, "value": 42}
    assert server.received == [{"version": 1, "action": "ping"}]


def test_request_helper_unavailable(tmp_path):
    with pytest.raises(protocol.HelperUnavailable):
        protocol.request_helper(tmp_path / "absent.sock", {"version": 1}, timeout_seconds=2)


def test_encode_rejects_oversized_message():
    big = {"payload": "x" * (protocol.MAX_REQUEST_BYTES + 1)}
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_message(big, maximum_bytes=protocol.MAX_REQUEST_BYTES)


def test_decode_rejects_duplicate_keys():
    payload = b'{"a": 1, "a": 2}'  # clé dupliquée littérale (json.dumps la supprimerait)
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_message(payload, maximum_bytes=1024)


def test_decode_rejects_non_dict():
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_message(b"[1, 2]", maximum_bytes=1024)


def test_decode_rejects_nan():
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_message(b'{"a": NaN}', maximum_bytes=1024)


def test_decode_rejects_truncated_payload():
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_message(b'{"a": ', maximum_bytes=1024)


def test_header_length_prefix_is_big_endian():
    encoded = protocol.encode_message({"a": 1}, maximum_bytes=1024)
    (length,) = struct.unpack("!I", encoded[:4])
    assert length == len(encoded) - 4
