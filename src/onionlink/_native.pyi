class Session:
    def __init__(
        self,
        bootstrap: str = "128.31.0.39:9131",
        consensus_file: str = "",
        timeout_ms: int = 30000,
        verbose: bool = False,
    ) -> None: ...

    def request(
        self,
        onion: str,
        port: int,
        payload: bytes = b"",
        response_limit: int = 4194304,
    ) -> bytes: ...

    def http_get(
        self,
        onion: str,
        port: int = 80,
        path: str = "/",
        response_limit: int = 4194304,
    ) -> bytes: ...
