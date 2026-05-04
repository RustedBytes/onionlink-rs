from __future__ import annotations

import asyncio
import json as jsonlib
from concurrent.futures import Executor
from dataclasses import dataclass
from functools import partial
from http import HTTPStatus
from typing import Callable, Iterable, Mapping, Sequence, TypeVar
from urllib.parse import urlencode

from ._native import Session as _NativeSession

Body = bytes | bytearray | memoryview | str | None
HeaderPairs = Iterable[tuple[str, str]]
Headers = Mapping[str, str] | HeaderPairs | None
Params = Mapping[str, str | int | float | bool | None] | Sequence[tuple[str, str | int | float | bool | None]] | None
Form = Mapping[str, str | int | float | bool | None] | Sequence[tuple[str, str | int | float | bool | None]] | None

_AsyncSessionT = TypeVar("_AsyncSessionT", bound="AsyncSession")
_T = TypeVar("_T")


@dataclass(frozen=True)
class Header:
    name: str
    value: str


@dataclass(frozen=True)
class Request:
    method: str
    onion: str
    port: int
    path: str
    headers: tuple[Header, ...]
    body: bytes
    response_limit: int
    http_version: str


@dataclass(frozen=True)
class Response:
    status_code: int
    reason: str
    headers: tuple[Header, ...]
    body: bytes
    raw: bytes
    http_version: str

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def text(self) -> str:
        return self.body.decode(self.encoding or "utf-8", errors="replace")

    @property
    def encoding(self) -> str | None:
        content_type = self.header("content-type")
        if not content_type:
            return None
        for part in content_type.split(";")[1:]:
            name, _, value = part.strip().partition("=")
            if name.lower() == "charset" and value:
                return value.strip("\"'")
        return None

    def header(self, name: str, default: str | None = None) -> str | None:
        needle = name.lower()
        for header in reversed(self.headers):
            if header.name.lower() == needle:
                return header.value
        return default

    def raise_for_status(self) -> None:
        if 400 <= self.status_code:
            try:
                phrase = HTTPStatus(self.status_code).phrase
            except ValueError:
                phrase = self.reason or "HTTP error"
            raise HTTPError(self.status_code, phrase, self)


class OnionLinkError(Exception):
    pass


class HTTPError(OnionLinkError):
    def __init__(self, status_code: int, reason: str, response: Response) -> None:
        super().__init__(f"{status_code} {reason}")
        self.status_code = status_code
        self.reason = reason
        self.response = response


class Session:
    def __init__(
        self,
        bootstrap: str = "128.31.0.39:9131",
        consensus_file: str = "",
        timeout_ms: int = 30000,
        verbose: bool = False,
    ) -> None:
        self._native = _NativeSession(
            bootstrap=bootstrap,
            consensus_file=consensus_file,
            timeout_ms=timeout_ms,
            verbose=verbose,
        )

    def raw_request(
        self,
        onion: str,
        port: int,
        payload: bytes = b"",
        response_limit: int = 4 * 1024 * 1024,
    ) -> bytes:
        return self._native.request(onion, port, payload, response_limit)

    def request(
        self,
        method: str,
        onion: str,
        *,
        port: int = 80,
        path: str = "/",
        params: Params = None,
        headers: Headers = None,
        body: Body = None,
        data: Body = None,
        json: object = None,
        form: Form = None,
        host: str | None = None,
        http_version: str = "HTTP/1.0",
        response_limit: int = 4 * 1024 * 1024,
    ) -> Response:
        body_inputs = sum(value is not None for value in (body, data, json, form))
        if body_inputs > 1:
            raise ValueError("use only one of body, data, json, or form")
        request_headers = list(_normalize_headers(headers))
        body_bytes = _prepare_body(body=body, data=data, json=json, form=form, headers=request_headers)
        normalized_path = _normalize_path(path, params)
        payload = self.build_http_request(
            method=method,
            onion=onion,
            path=normalized_path,
            headers=tuple(request_headers),
            body=body_bytes,
            host=host,
            http_version=http_version,
        )
        raw = self.raw_request(onion, port, payload, response_limit)
        return parse_response(raw)

    def build_http_request(
        self,
        *,
        method: str,
        onion: str,
        path: str = "/",
        headers: Headers = None,
        body: Body = None,
        host: str | None = None,
        http_version: str = "HTTP/1.0",
    ) -> bytes:
        return _build_http_request(
            method=method,
            onion=onion,
            path=path,
            headers=headers,
            body=body,
            host=host,
            http_version=http_version,
        )

    def get(self, onion: str, **kwargs: object) -> Response:
        return self.request("GET", onion, **kwargs)

    def http_get(
        self,
        onion: str,
        port: int = 80,
        path: str = "/",
        response_limit: int = 4 * 1024 * 1024,
    ) -> bytes:
        return self.get(
            onion,
            port=port,
            path=path,
            response_limit=response_limit,
        ).body

    def head(self, onion: str, **kwargs: object) -> Response:
        return self.request("HEAD", onion, **kwargs)

    def post(self, onion: str, **kwargs: object) -> Response:
        return self.request("POST", onion, **kwargs)

    def put(self, onion: str, **kwargs: object) -> Response:
        return self.request("PUT", onion, **kwargs)

    def patch(self, onion: str, **kwargs: object) -> Response:
        return self.request("PATCH", onion, **kwargs)

    def delete(self, onion: str, **kwargs: object) -> Response:
        return self.request("DELETE", onion, **kwargs)

    def options(self, onion: str, **kwargs: object) -> Response:
        return self.request("OPTIONS", onion, **kwargs)


class AsyncSession:
    """Asyncio wrapper around Session.

    Blocking native initialization and requests use native awaitables when
    available, with an executor fallback for older bindings. Cancelling an
    awaited request stops waiting for the result, but the underlying native
    task or worker thread may continue until the operation finishes or times out.
    """

    def __init__(
        self,
        bootstrap: str = "128.31.0.39:9131",
        consensus_file: str = "",
        timeout_ms: int = 30000,
        verbose: bool = False,
        *,
        executor: Executor | None = None,
    ) -> None:
        self._bootstrap = bootstrap
        self._consensus_file = consensus_file
        self._timeout_ms = timeout_ms
        self._verbose = verbose
        self._executor = executor
        self._session: Session | None = None
        self._init_lock: asyncio.Lock | None = None

    @classmethod
    async def create(
        cls: type[_AsyncSessionT],
        bootstrap: str = "128.31.0.39:9131",
        consensus_file: str = "",
        timeout_ms: int = 30000,
        verbose: bool = False,
        *,
        executor: Executor | None = None,
    ) -> _AsyncSessionT:
        session = cls(
            bootstrap=bootstrap,
            consensus_file=consensus_file,
            timeout_ms=timeout_ms,
            verbose=verbose,
            executor=executor,
        )
        await session._get_session()
        return session

    async def __aenter__(self: _AsyncSessionT) -> _AsyncSessionT:
        await self._get_session()
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None

    async def _get_session(self) -> Session:
        if self._session is not None:
            return self._session
        lock = self._get_init_lock()
        async with lock:
            if self._session is None:
                native_create = getattr(_NativeSession, "create_async", None)
                if native_create is None:
                    self._session = await self._run(
                        partial(
                            Session,
                            bootstrap=self._bootstrap,
                            consensus_file=self._consensus_file,
                            timeout_ms=self._timeout_ms,
                            verbose=self._verbose,
                        )
                    )
                else:
                    native = await native_create(
                        bootstrap=self._bootstrap,
                        consensus_file=self._consensus_file,
                        timeout_ms=self._timeout_ms,
                        verbose=self._verbose,
                    )
                    self._session = Session.__new__(Session)
                    self._session._native = native
            return self._session

    def _get_init_lock(self) -> asyncio.Lock:
        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
        return self._init_lock

    async def _run(self, func: Callable[[], _T]) -> _T:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, func)

    async def raw_request(
        self,
        onion: str,
        port: int,
        payload: bytes = b"",
        response_limit: int = 4 * 1024 * 1024,
    ) -> bytes:
        session = await self._get_session()
        request_async = getattr(session._native, "request_async", None)
        if request_async is not None:
            return await request_async(onion, port, payload, response_limit)
        return await self._run(partial(session.raw_request, onion, port, payload, response_limit))

    async def request(
        self,
        method: str,
        onion: str,
        *,
        port: int = 80,
        path: str = "/",
        params: Params = None,
        headers: Headers = None,
        body: Body = None,
        data: Body = None,
        json: object = None,
        form: Form = None,
        host: str | None = None,
        http_version: str = "HTTP/1.0",
        response_limit: int = 4 * 1024 * 1024,
    ) -> Response:
        body_inputs = sum(value is not None for value in (body, data, json, form))
        if body_inputs > 1:
            raise ValueError("use only one of body, data, json, or form")
        request_headers = list(_normalize_headers(headers))
        body_bytes = _prepare_body(body=body, data=data, json=json, form=form, headers=request_headers)
        normalized_path = _normalize_path(path, params)
        payload = self.build_http_request(
            method=method,
            onion=onion,
            path=normalized_path,
            headers=tuple(request_headers),
            body=body_bytes,
            host=host,
            http_version=http_version,
        )
        raw = await self.raw_request(onion, port, payload, response_limit)
        return parse_response(raw)

    def build_http_request(
        self,
        *,
        method: str,
        onion: str,
        path: str = "/",
        headers: Headers = None,
        body: Body = None,
        host: str | None = None,
        http_version: str = "HTTP/1.0",
    ) -> bytes:
        return _build_http_request(
            method=method,
            onion=onion,
            path=path,
            headers=headers,
            body=body,
            host=host,
            http_version=http_version,
        )

    async def get(self, onion: str, **kwargs: object) -> Response:
        return await self.request("GET", onion, **kwargs)

    async def http_get(
        self,
        onion: str,
        port: int = 80,
        path: str = "/",
        response_limit: int = 4 * 1024 * 1024,
    ) -> bytes:
        return (
            await self.get(
                onion,
                port=port,
                path=path,
                response_limit=response_limit,
            )
        ).body

    async def head(self, onion: str, **kwargs: object) -> Response:
        return await self.request("HEAD", onion, **kwargs)

    async def post(self, onion: str, **kwargs: object) -> Response:
        return await self.request("POST", onion, **kwargs)

    async def put(self, onion: str, **kwargs: object) -> Response:
        return await self.request("PUT", onion, **kwargs)

    async def patch(self, onion: str, **kwargs: object) -> Response:
        return await self.request("PATCH", onion, **kwargs)

    async def delete(self, onion: str, **kwargs: object) -> Response:
        return await self.request("DELETE", onion, **kwargs)

    async def options(self, onion: str, **kwargs: object) -> Response:
        return await self.request("OPTIONS", onion, **kwargs)


def parse_response(raw: bytes) -> Response:
    header_blob, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        header_blob, sep, body = raw.partition(b"\n\n")
    if not sep:
        return Response(0, "", (), raw, raw, "")

    lines = header_blob.replace(b"\r\n", b"\n").split(b"\n")
    status_line = lines[0].decode("iso-8859-1", errors="replace")
    http_version, status_code, reason = _parse_status_line(status_line)
    headers = tuple(_parse_header(line) for line in lines[1:] if line.strip())
    if _header_value(headers, "transfer-encoding", "").lower() == "chunked":
        body = _decode_chunked(body)
    return Response(status_code, reason, headers, body, raw, http_version)


def _parse_status_line(line: str) -> tuple[str, int, str]:
    version, _, rest = line.partition(" ")
    code_text, _, reason = rest.partition(" ")
    try:
        code = int(code_text)
    except ValueError:
        code = 0
    return version, code, reason


def _parse_header(line: bytes) -> Header:
    name, _, value = line.partition(b":")
    return Header(
        name.decode("iso-8859-1", errors="replace").strip(),
        value.decode("iso-8859-1", errors="replace").strip(),
    )


def _normalize_headers(headers: Headers) -> tuple[tuple[str, str], ...]:
    if headers is None:
        return ()
    if isinstance(headers, Mapping):
        return tuple((str(name), str(value)) for name, value in headers.items())
    return tuple((str(name), str(value)) for name, value in headers)


def _build_http_request(
    *,
    method: str,
    onion: str,
    path: str = "/",
    headers: Headers = None,
    body: Body = None,
    host: str | None = None,
    http_version: str = "HTTP/1.0",
) -> bytes:
    method = method.upper()
    body_bytes = _body_to_bytes(body)
    header_pairs = list(_normalize_headers(headers))
    header_names = {name.lower() for name, _ in header_pairs}
    if "host" not in header_names:
        header_pairs.insert(0, ("Host", host or onion.lower()))
    if "connection" not in header_names:
        header_pairs.append(("Connection", "close"))
    if body_bytes and "content-length" not in header_names:
        header_pairs.append(("Content-Length", str(len(body_bytes))))
    start = f"{method} {_normalize_path(path, None)} {http_version}\r\n"
    head = start + "".join(f"{name}: {value}\r\n" for name, value in header_pairs) + "\r\n"
    return head.encode("ascii") + body_bytes


def _prepare_body(
    *,
    body: Body,
    data: Body,
    json: object,
    form: Form,
    headers: list[tuple[str, str]],
) -> bytes:
    header_names = {name.lower() for name, _ in headers}
    if json is not None:
        if "content-type" not in header_names:
            headers.append(("Content-Type", "application/json"))
        return jsonlib.dumps(json, separators=(",", ":")).encode("utf-8")
    if form is not None:
        if "content-type" not in header_names:
            headers.append(("Content-Type", "application/x-www-form-urlencoded"))
        return urlencode(
            [(key, value) for key, value in _iter_params(form) if value is not None],
            doseq=True,
        ).encode("ascii")
    return _body_to_bytes(data if data is not None else body)


def _normalize_path(path: str, params: Params) -> str:
    normalized = path or "/"
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if params:
        query = urlencode(
            [(key, value) for key, value in _iter_params(params) if value is not None],
            doseq=True,
        )
        joiner = "&" if "?" in normalized else "?"
        normalized = normalized + joiner + query
    return normalized


def _iter_params(params: Params) -> Iterable[tuple[str, str | int | float | bool | None]]:
    if params is None:
        return ()
    if isinstance(params, Mapping):
        return params.items()
    return params


def _body_to_bytes(body: Body) -> bytes:
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    return bytes(body)


def _header_value(headers: Iterable[Header], name: str, default: str = "") -> str:
    needle = name.lower()
    for header in reversed(tuple(headers)):
        if header.name.lower() == needle:
            return header.value
    return default


def _decode_chunked(body: bytes) -> bytes:
    out = bytearray()
    pos = 0
    while True:
        line_end = body.find(b"\r\n", pos)
        line_sep_len = 2
        if line_end < 0:
            line_end = body.find(b"\n", pos)
            line_sep_len = 1
        if line_end < 0:
            return bytes(out)
        size_text = body[pos:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return body
        pos = line_end + line_sep_len
        if size == 0:
            return bytes(out)
        out.extend(body[pos : pos + size])
        pos += size
        if body[pos : pos + 2] == b"\r\n":
            pos += 2
        elif body[pos : pos + 1] == b"\n":
            pos += 1
