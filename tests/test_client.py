from __future__ import annotations

import sys
import types


class _NativeSession:
    def __init__(
        self,
        bootstrap: str = "128.31.0.39:9131",
        consensus_file: str = "",
        timeout_ms: int = 30000,
        verbose: bool = False,
    ) -> None:
        self.bootstrap = bootstrap
        self.consensus_file = consensus_file
        self.timeout_ms = timeout_ms
        self.verbose = verbose
        self.requests: list[tuple[str, int, bytes, int]] = []

    def request(
        self,
        onion: str,
        port: int,
        payload: bytes = b"",
        response_limit: int = 4194304,
    ) -> bytes:
        self.requests.append((onion, port, payload, response_limit))
        return b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nok"

    def http_get(
        self,
        onion: str,
        port: int = 80,
        path: str = "/",
        response_limit: int = 4194304,
    ) -> bytes:
        return b"ok"


fake_native = types.ModuleType("onionlink._native")
fake_native.Session = _NativeSession
sys.modules.setdefault("onionlink._native", fake_native)

from onionlink import RawSession, Session, parse_response  # noqa: E402


def test_raw_session_export_uses_native_session() -> None:
    assert RawSession is _NativeSession


def test_build_http_request_defaults_and_body_bytes() -> None:
    session = Session()
    payload = session.build_http_request(
        method="post",
        onion="ExampleExampleExampleExampleExampleExampleExampleExampleExampleExample.onion",
        path="api/items",
        headers={"Accept": "application/json"},
        body=b'{"ok":true}',
    )
    assert payload.startswith(
        b"POST /api/items HTTP/1.0\r\n"
        b"Host: exampleexampleexampleexampleexampleexampleexampleexampleexampleexample.onion\r\n"
        b"Accept: application/json\r\n"
    )
    assert b"Connection: close\r\n" in payload
    assert b"Content-Length: 11\r\n" in payload
    assert payload.endswith(b"\r\n\r\n{\"ok\":true}")


def test_request_builds_query_json_and_parses_response() -> None:
    session = Session()
    response = session.request(
        "POST",
        "exampleexampleexampleexampleexampleexampleexampleexampleexampleexample.onion",
        path="/items",
        params={"trace": "1"},
        json={"name": "test"},
    )
    assert response.status_code == 200
    assert response.body == b"ok"
    onion, port, payload, response_limit = session._native.requests[-1]
    assert onion.endswith(".onion")
    assert port == 80
    assert response_limit == 4 * 1024 * 1024
    assert payload.startswith(b"POST /items?trace=1 HTTP/1.0\r\n")
    assert b"Content-Type: application/json\r\n" in payload
    assert payload.endswith(b'\r\n\r\n{"name":"test"}')


def test_parse_response_decodes_chunked_body() -> None:
    response = parse_response(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n"
    )
    assert response.status_code == 200
    assert response.body == b"hello"
    assert response.ok

