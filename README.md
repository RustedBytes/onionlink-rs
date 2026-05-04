# onionlink

`onionlink` is a small Rust Tor v3 onion-service client with Python bindings. It talks directly to Tor relays, builds the minimum circuits needed for v3 onion-service access, and can exchange raw bytes or a simple HTTP request with the service.

Security and anonymity are explicit non-goals. This is a protocol experiment and interoperability tool, not a replacement for Tor Browser, Arti, or the Tor daemon.

## What It Implements

- Downloads and parses the live microdescriptor consensus.
- Hydrates relay microdescriptors to obtain Ed25519 identities and ntor keys.
- Derives the v3 onion-service blinded key and subcredential.
- Selects HSDirs and fetches the v3 descriptor over a guarded `EXTEND2` circuit.
- Decrypts unprotected v3 onion-service descriptors.
- Parses introduction points, including link specifiers, intro ntor keys, auth keys, and service encryption keys.
- Establishes a rendezvous point over a guarded `EXTEND2` circuit.
- Sends `INTRODUCE1` over a guarded intro-point circuit.
- Completes hs-ntor from `RENDEZVOUS2`.
- Opens a stream to `:<port>` and sends/receives relay data.

## Dependencies

- Rust 1.83 or newer
- Python 3.10 or newer for the Python package
- `maturin` for Python wheel builds

On Arch Linux:

```sh
sudo pacman -S rust python python-pip
```

On Debian/Ubuntu-style systems:

```sh
sudo apt install build-essential curl python3 python3-pip
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Build

```sh
cargo build --workspace
```

Build Linux Python wheels with Docker:

```sh
docker build --target wheels --output type=local,dest=dist .
```

This writes Python 3.10+ manylinux wheels into `dist/`, including `cp313t`
and `cp314t` free-threaded wheels. The wheel build is Linux-only and uses
`maturin` to build the PyO3 extension.

Build a wheel directly on a Linux host with the native dependencies installed:

```sh
python -m pip wheel . -w dist
```

Run deterministic Rust parity tests:

```sh
cargo test --workspace
```

Run Python API tests after installing the test extra:

```sh
python -m pip install -e '.[test]'
PYTHONPATH=src python -m pytest
```

## Python Client

The Python package exposes an OOP session API. A `Session` downloads the
microdescriptor consensus and hydrates relay microdescriptors once, then reuses
that directory state for multiple onion-service requests. Request methods release
the Python GIL while doing network work, so one initialized session can be used
from `asyncio.to_thread`, a `ThreadPoolExecutor`, or regular worker threads.

```python
from concurrent.futures import ThreadPoolExecutor

from onionlink import Session

session = Session(timeout_ms=30_000, verbose=False)

def fetch(onion: str) -> bytes:
    return session.get(onion, port=80, path="/").body

onions = [
    "archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion",
]

with ThreadPoolExecutor(max_workers=4) as pool:
    for body in pool.map(fetch, onions):
        print(body[:200])
```

For native `asyncio` call sites, use `AsyncSession`. It keeps the synchronous
API available and uses the native PyO3/Tokio awaitables when the compiled
extension is available:

```python
import asyncio

from onionlink import AsyncSession


async def main() -> None:
    async with AsyncSession(timeout_ms=30_000) as session:
        response = await session.get(
            "archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion",
            port=80,
            path="/",
        )
        print(response.status_code, response.body[:200])


asyncio.run(main())
```

Cancelling an awaited async request stops waiting for its result, but the
underlying native blocking task can continue until the request finishes or the
configured `timeout_ms` is reached.

The PyO3 extension declares `gil_used = false`, and native bootstrap/request
work detaches from the Python runtime while running. Free-threaded wheels are
therefore built for `py313t` and `py314t` without re-enabling the GIL on import.

Raw request bytes are also supported:

```python
from onionlink import Session

session = Session(bootstrap="128.31.0.39:9131", timeout_ms=30_000)
response = session.raw_request(
    "exampleexampleexampleexampleexampleexampleexampleexampleexampleexample.onion",
    1234,
    b"hello\n",
)
```

Use `request()` for full HTTP control:

```python
from onionlink import Session

session = Session(timeout_ms=30_000)
response = session.request(
    "POST",
    "exampleexampleexampleexampleexampleexampleexampleexampleexampleexample.onion",
    port=80,
    path="/api/items",
    params={"trace": "1"},
    headers={"Accept": "application/json"},
    json={"name": "test"},
    response_limit=8 * 1024 * 1024,
)

response.raise_for_status()
print(response.status_code, response.header("content-type"))
print(response.text)
```

`Session` constructor arguments:

- `bootstrap`: HTTP directory cache as `host:port`.
- `consensus_file`: optional local `consensus-microdesc` file.
- `timeout_ms`: TCP/TLS read timeout.
- `verbose`: print native bootstrap and rendezvous progress to stderr.

Request methods:

- `request(method, onion, *, port=80, path="/", params=None, headers=None, body=None, data=None, json=None, form=None, host=None, http_version="HTTP/1.0", response_limit=4194304) -> Response`
- `get/head/post/put/patch/delete/options(onion, **request_options) -> Response`
- `raw_request(onion, port, payload=b"", response_limit=4194304) -> bytes`

`AsyncSession` exposes the same request methods as awaitables, plus
`await AsyncSession.create(...)` for eager initialization and
`async with AsyncSession(...)` for context-manager style initialization.

`Response` exposes `status_code`, `reason`, `headers`, `body`, `raw`,
`http_version`, `ok`, `text`, `encoding`, `header(name)`, and
`raise_for_status()`.

## Usage

```sh
cargo run -p onionlink-cli -- <service-v3-address>.onion <port> [options]
```

Fetch `/` over HTTP from the container:

```sh
docker run --rm onionlink \
  archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion 80 \
  --http-get / \
  --verbose
```

Send raw text:

```sh
cargo run -p onionlink-cli -- <service-v3-address>.onion 1234 --send "hello"
```

Forward standard input:

```sh
printf 'hello\n' | cargo run -p onionlink-cli -- <service-v3-address>.onion 1234 --stdin
```

## Options

- `--bootstrap host:port` selects the HTTP directory cache used for bootstrap.
  The default is `128.31.0.39:9131`.
- `--consensus-file path` uses a local microdescriptor consensus instead of downloading one.
- `--timeout-ms n` sets TCP/TLS read timeouts. The default is `30000`.
- `--http-get [path]` sends a simple HTTP/1.0 GET after connecting. If `path` is omitted, `/` is used.
- `--send text` sends raw text after the stream opens.
- `--stdin` forwards standard input after the stream opens.
- `--verbose` enables progress logging for bootstrap, descriptor, intro, rendezvous, and stream activity.

Logging uses `env_logger`. `--verbose` defaults the CLI log level to `info`; set
`RUST_LOG` for more control, for example:

```sh
RUST_LOG=onionlink_core=debug,onionlink=info cargo run -p onionlink-cli -- <service-v3-address>.onion 80 --http-get /
```

If no send mode is provided, `--http-get /` is used by default.

## Limitations

The implementation intentionally omits substantial parts of a real Tor client:

- no consensus, directory, relay, descriptor, or certificate signature validation;
- no relay-family, guard, path-bias, or anonymity-aware path selection;
- no bridges, pluggable transports, proxies, IPv6 dialing, or DNS helpers;
- no onion-service client authorization;
- no proof-of-work support for protected services;
- no authenticated SENDMEs or modern congestion-control behavior;
- no stream isolation, SOCKS server, circuit pooling, or persistent state;
- no traffic shaping or padding.

The client uses direct TLS connections to selected relays and short guarded circuits only where current relays require them, such as HSDir descriptor fetches, rendezvous establishment, and intro-point delivery.

## Notes

The default bootstrap source is a public Tor directory authority/cache endpoint.
Live behavior depends on relay reachability, descriptor availability, and the onion service accepting a connection at the requested port.
