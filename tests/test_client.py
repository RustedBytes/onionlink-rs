from __future__ import annotations

import asyncio
import sys
import types
from typing import List, Tuple

ONION = "exampleexampleexampleexampleexampleexampleexampleexampleexampleexample.onion"


class _NativeSession:
    instances: List["_NativeSession"] = []
    async_creates = 0
    async_requests: List[Tuple[str, int, bytes, int]] = []

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
        self.requests: List[Tuple[str, int, bytes, int]] = []
        self.instances.append(self)

    def request(
        self,
        onion: str,
        port: int,
        payload: bytes = b"",
        response_limit: int = 4194304,
    ) -> bytes:
        self.requests.append((onion, port, payload, response_limit))
        return b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nok"

    @classmethod
    async def create_async(
        cls,
        bootstrap: str = "128.31.0.39:9131",
        consensus_file: str = "",
        timeout_ms: int = 30000,
        verbose: bool = False,
    ) -> _NativeSession:
        cls.async_creates += 1
        return cls(
            bootstrap=bootstrap,
            consensus_file=consensus_file,
            timeout_ms=timeout_ms,
            verbose=verbose,
        )

    async def request_async(
        self,
        onion: str,
        port: int,
        payload: bytes = b"",
        response_limit: int = 4194304,
    ) -> bytes:
        self.async_requests.append((onion, port, payload, response_limit))
        return self.request(onion, port, payload, response_limit)

    def http_get(
        self,
        onion: str,
        port: int = 80,
        path: str = "/",
        response_limit: int = 4194304,
    ) -> bytes:
        return b"ok"

    async def http_get_async(
        self,
        onion: str,
        port: int = 80,
        path: str = "/",
        response_limit: int = 4194304,
    ) -> bytes:
        return self.http_get(onion, port, path, response_limit)


fake_native = types.ModuleType("onionlink._native")
fake_native.Session = _NativeSession
sys.modules.setdefault("onionlink._native", fake_native)

from onionlink import AsyncSession, RawSession, Session, parse_response  # noqa: E402


def _reset_native() -> None:
    _NativeSession.instances.clear()
    _NativeSession.async_creates = 0
    _NativeSession.async_requests.clear()


def test_raw_session_export_uses_native_session() -> None:
    assert RawSession is _NativeSession


def test_build_http_request_defaults_and_body_bytes() -> None:
    session = Session()
    payload = session.build_http_request(
        method="post",
        onion=ONION,
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
        ONION,
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


def test_async_session_is_lazy_until_awaited() -> None:
    _reset_native()
    session = AsyncSession()

    payload = session.build_http_request(method="get", onion=ONION, path="")

    assert _NativeSession.instances == []
    assert payload.startswith(b"GET / HTTP/1.0\r\n")

    async def run() -> None:
        response = await session.get(ONION)
        assert response.status_code == 200
        assert response.body == b"ok"
        assert await session.http_get(ONION) == b"ok"

    asyncio.run(run())

    assert len(_NativeSession.instances) == 1
    assert _NativeSession.async_creates == 1


def test_async_request_builds_query_json_and_parses_response() -> None:
    _reset_native()

    async def run() -> None:
        session = AsyncSession()
        response = await session.request(
            "POST",
            ONION,
            path="/items",
            params={"trace": "1"},
            json={"name": "test"},
        )

        assert response.status_code == 200
        assert response.body == b"ok"
        assert session._session is not None
        onion, port, payload, response_limit = session._session._native.requests[-1]
        assert onion == ONION
        assert port == 80
        assert response_limit == 4 * 1024 * 1024
        assert payload.startswith(b"POST /items?trace=1 HTTP/1.0\r\n")
        assert b"Content-Type: application/json\r\n" in payload
        assert payload.endswith(b'\r\n\r\n{"name":"test"}')

    asyncio.run(run())
    assert len(_NativeSession.async_requests) == 1


def test_async_raw_request_passes_arguments_through() -> None:
    _reset_native()

    async def run() -> None:
        session = AsyncSession()
        response = await session.raw_request(ONION, 1234, b"hello", 99)

        assert response.endswith(b"\r\n\r\nok")
        assert session._session is not None
        assert session._session._native.requests[-1] == (ONION, 1234, b"hello", 99)

    asyncio.run(run())
    assert _NativeSession.async_requests == [(ONION, 1234, b"hello", 99)]


def test_async_concurrent_first_calls_share_one_session() -> None:
    _reset_native()

    async def run() -> None:
        session = AsyncSession()

        responses = await asyncio.gather(
            session.get(ONION),
            session.head(ONION),
        )

        assert [response.body for response in responses] == [b"ok", b"ok"]
        assert len(_NativeSession.instances) == 1
        assert session._session is not None
        payload_methods = {
            request[2].split(b" ", 1)[0]
            for request in session._session._native.requests
        }
        assert payload_methods == {b"GET", b"HEAD"}

    asyncio.run(run())


def test_async_create_and_context_manager_initialize() -> None:
    _reset_native()

    async def run() -> None:
        created = await AsyncSession.create(timeout_ms=123)
        assert created._session is not None
        assert _NativeSession.instances[-1].timeout_ms == 123

        async with AsyncSession(verbose=True) as managed:
            assert managed._session is not None
            assert _NativeSession.instances[-1].verbose is True

    asyncio.run(run())

    assert len(_NativeSession.instances) == 2


def test_parse_response_decodes_chunked_body() -> None:
    response = parse_response(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n"
    )
    assert response.status_code == 200
    assert response.body == b"hello"
    assert response.ok
