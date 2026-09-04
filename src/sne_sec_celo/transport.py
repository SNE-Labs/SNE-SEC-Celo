"""Bounded HTTP transport pinned to a previously admitted public address."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from dataclasses import dataclass

from .canonical import digest
from .errors import CollectionFailed
from .targets import AdmittedResolution, validate_connected_peer

MAX_HEADER_BYTES = 65_536


@dataclass(frozen=True)
class HttpExchange:
    status_code: int
    headers: tuple[tuple[str, str], ...]
    selected_address: str
    connected_peer: str
    receipt_digest: str

    def values(self, name: str) -> tuple[str, ...]:
        normalized = name.lower()
        return tuple(value for key, value in self.headers if key == normalized)


class PinnedHttpTransport:
    def __init__(self, *, timeout_seconds: int = 10) -> None:
        if timeout_seconds < 1 or timeout_seconds > 30:
            raise ValueError("transport timeout must be between 1 and 30 seconds")
        self._timeout = timeout_seconds

    async def fetch(self, resolution: AdmittedResolution) -> HttpExchange:
        target = resolution.target
        ssl_context = ssl.create_default_context() if target.scheme == "https" else None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=str(resolution.selected_address),
                    port=target.port,
                    ssl=ssl_context,
                    server_hostname=target.host if ssl_context else None,
                    limit=MAX_HEADER_BYTES,
                ),
                timeout=self._timeout,
            )
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            raise CollectionFailed("connection to admitted destination failed") from exc

        try:
            peer_info = writer.get_extra_info("peername")
            if not isinstance(peer_info, tuple) or not peer_info:
                raise CollectionFailed("transport did not expose the connected peer")
            peer = str(peer_info[0])
            validate_connected_peer(peer, resolution)
            request = (
                f"GET {target.path_and_query} HTTP/1.1\r\n"
                f"Host: {target.authority}\r\n"
                "User-Agent: SNE-SEC-Celo-Reference/1.0\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=self._timeout)
            try:
                raw_headers = await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), timeout=self._timeout
                )
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
                raise CollectionFailed(
                    "HTTP response headers were incomplete or oversized"
                ) from exc
            status, headers = _parse_headers(raw_headers)
            receipt = digest(
                {
                    "status_code": status,
                    "header_digest": digest(headers),
                    "selected_address": str(resolution.selected_address),
                    "connected_peer": peer,
                    "network_policy_version": resolution.policy_version,
                }
            )
            return HttpExchange(status, headers, str(resolution.selected_address), peer, receipt)
        except (OSError, TimeoutError, UnicodeError) as exc:
            raise CollectionFailed("bounded HTTP exchange failed") from exc
        finally:
            writer.close()
            with contextlib.suppress(OSError, TimeoutError, ssl.SSLError):
                await asyncio.wait_for(writer.wait_closed(), timeout=1)


def _parse_headers(raw: bytes) -> tuple[int, tuple[tuple[str, str], ...]]:
    if len(raw) > MAX_HEADER_BYTES:
        raise CollectionFailed("HTTP response headers exceeded the configured limit")
    try:
        lines = raw.decode("iso-8859-1").split("\r\n")
        protocol, status_text, *_ = lines[0].split(" ", 2)
        status = int(status_text)
    except (UnicodeError, ValueError) as exc:
        raise CollectionFailed("HTTP status line was malformed") from exc
    if not protocol.startswith("HTTP/") or not 100 <= status <= 599:
        raise CollectionFailed("HTTP status line was outside the accepted grammar")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            break
        if line[0] in " \t" or ":" not in line:
            raise CollectionFailed("HTTP response contains malformed or folded headers")
        name, value = line.split(":", 1)
        normalized = name.strip().lower()
        if not normalized or any(ord(char) < 33 or ord(char) > 126 for char in normalized):
            raise CollectionFailed("HTTP response header name is invalid")
        headers.append((normalized, value.strip()))
    return status, tuple(headers)
