"""Tor transport.

Wraps an ``httpx.AsyncClient`` configured to route every request through the
Tor SOCKS proxy, so ``.onion`` hidden services resolve and connect. Also offers
a connectivity self-check and optional circuit rotation via the Tor control
port (NEWNYM).
"""
from __future__ import annotations

import socket
from contextlib import closing

import httpx

from .config import Settings


class TorClient:
    """Async HTTP client bound to the Tor SOCKS proxy."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._client: httpx.AsyncClient | None = None
        self._requests = 0

    async def __aenter__(self) -> "TorClient":
        self._client = httpx.AsyncClient(
            proxy=self.settings.tor_proxy,
            timeout=self.settings.request_timeout,
            headers={"User-Agent": self.settings.user_agent},
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client:
            await self._client.aclose()

    async def get(self, url: str, cookie: str = "") -> httpx.Response:
        assert self._client is not None, "use TorClient as an async context manager"
        headers = {"Cookie": cookie} if cookie else {}
        resp = await self._client.get(url, headers=headers)
        self._requests += 1
        if (
            self.settings.circuit_rotation_every
            and self._requests % self.settings.circuit_rotation_every == 0
        ):
            self.new_circuit()
        return resp

    # --- diagnostics -------------------------------------------------------
    def proxy_reachable(self) -> bool:
        """TCP-connect to the SOCKS proxy host:port without sending traffic."""
        host, port = _parse_proxy_hostport(self.settings.tor_proxy)
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(5)
            return s.connect_ex((host, port)) == 0

    async def check(self) -> dict:
        """Verify Tor egress via the project's official check endpoint."""
        if not self.proxy_reachable():
            return {"ok": False, "reason": "SOCKS proxy not reachable"}
        try:
            r = await self.get("https://check.torproject.org/api/ip")
            data = r.json()
            return {"ok": bool(data.get("IsTor")), "exit_ip": data.get("IP")}
        except Exception as exc:  # noqa: BLE001 - report any failure to caller
            return {"ok": False, "reason": str(exc)}

    def new_circuit(self) -> bool:
        """Request a fresh Tor circuit via the control port (NEWNYM)."""
        try:
            with closing(socket.create_connection(
                ("127.0.0.1", self.settings.tor_control_port), timeout=5
            )) as ctrl:
                pw = self.settings.tor_control_password
                ctrl.sendall(f'AUTHENTICATE "{pw}"\r\n'.encode())
                if b"250" not in ctrl.recv(1024):
                    return False
                ctrl.sendall(b"SIGNAL NEWNYM\r\n")
                return b"250" in ctrl.recv(1024)
        except OSError:
            return False


def _parse_proxy_hostport(proxy: str) -> tuple[str, int]:
    rest = proxy.split("://", 1)[-1]
    host, _, port = rest.partition(":")
    return host or "127.0.0.1", int(port or "9050")
