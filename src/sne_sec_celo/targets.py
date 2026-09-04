"""Origin normalization and fail-closed network admission."""

from __future__ import annotations

import asyncio
import ipaddress
import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from urllib.parse import SplitResult, urljoin, urlsplit

from .errors import TargetRejected

IPAddress = IPv4Address | IPv6Address
NETWORK_POLICY_VERSION = "sne-sec-celo-network-policy-1"

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_FORBIDDEN_NAMES = frozenset(
    {"localhost", "localhost.localdomain", "metadata.google.internal", "metadata.azure.internal"}
)
_FORBIDDEN_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".home.arpa",
    ".test",
    ".invalid",
    ".example",
    ".onion",
)
_DENIED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001:db8::/32",
        "2001:10::/28",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


@dataclass(frozen=True)
class CollectionURL:
    scheme: str
    host: str
    port: int
    path_and_query: str

    @property
    def authority(self) -> str:
        value = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if self.scheme == "https" else 80
        return value if self.port == default else f"{value}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.authority}{self.path_and_query}"

    @property
    def public_source(self) -> str:
        path = self.path_and_query.split("?", 1)[0]
        return f"{self.scheme}://{self.authority}{path}"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.authority}"


@dataclass(frozen=True)
class AdmittedResolution:
    target: CollectionURL
    addresses: tuple[IPAddress, ...]
    selected_address: IPAddress
    policy_version: str = NETWORK_POLICY_VERSION


def _split(value: str) -> SplitResult:
    candidate = value.strip()
    if not candidate:
        raise TargetRejected("target is empty")
    if any(ord(char) < 32 for char in candidate):
        raise TargetRejected("target contains control characters")
    if "\\" in candidate or len(candidate) > 4096:
        raise TargetRejected("target contains a backslash or is too long")
    if "://" not in candidate:
        candidate = "https://" + candidate
    try:
        return urlsplit(candidate)
    except ValueError as exc:
        raise TargetRejected("target is not a valid URL") from exc


def validate_public_ip(value: str | IPAddress) -> IPAddress:
    try:
        address = (
            value
            if isinstance(value, (IPv4Address, IPv6Address))
            else ipaddress.ip_address(value)
        )
    except ValueError as exc:
        raise TargetRejected("DNS returned a malformed IP address") from exc
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if not address.is_global or any(address in network for network in _DENIED_NETWORKS):
        raise TargetRejected(f"destination address is not globally routable: {address}")
    return address


def _normalize_host(raw: str) -> str:
    value = raw.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is not None:
        return str(validate_public_ip(address))
    try:
        host = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetRejected("target host cannot be encoded as IDNA") from exc
    if len(host) > 253:
        raise TargetRejected("target host is too long")
    labels = host.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise TargetRejected("target must be a valid public DNS name")
    if host in _FORBIDDEN_NAMES or host.endswith(_FORBIDDEN_SUFFIXES):
        raise TargetRejected("target belongs to a non-public namespace")
    return host


def normalize_origin(value: str) -> CollectionURL:
    """Normalize an input to an HTTPS origin; user paths and queries are discarded."""

    parsed = _split(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetRejected("only HTTP and HTTPS targets are supported")
    if parsed.username is not None or parsed.password is not None or not parsed.hostname:
        raise TargetRejected("target authority is missing or contains forbidden userinfo")
    try:
        supplied_port = parsed.port
    except ValueError as exc:
        raise TargetRejected("target port is invalid") from exc
    expected = 80 if parsed.scheme.lower() == "http" else 443
    if supplied_port is not None and supplied_port != expected:
        raise TargetRejected("only standard HTTP and HTTPS ports are admitted")
    return CollectionURL("https", _normalize_host(parsed.hostname), 443, "/")


def normalize_redirect(value: str, *, base_url: str) -> CollectionURL:
    candidate = urljoin(base_url, value)
    parsed = _split(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise TargetRejected("redirect uses a forbidden scheme")
    if parsed.username is not None or parsed.password is not None or not parsed.hostname:
        raise TargetRejected("redirect authority is missing or contains forbidden userinfo")
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise TargetRejected("redirect port is invalid") from exc
    if port != (443 if scheme == "https" else 80):
        raise TargetRejected("redirect uses a non-standard port")
    path = parsed.path or "/"
    if not path.startswith("/"):
        raise TargetRejected("redirect path is not absolute")
    path_and_query = path + (f"?{parsed.query}" if parsed.query else "")
    return CollectionURL(scheme, _normalize_host(parsed.hostname), port, path_and_query)


def admit_resolution(target: CollectionURL, values: tuple[str, ...]) -> AdmittedResolution:
    addresses: set[IPAddress] = set()
    for value in values:
        addresses.add(validate_public_ip(value))
    if not addresses:
        raise TargetRejected("target did not resolve to an admitted address")
    ordered = tuple(sorted(addresses, key=lambda item: (item.version, int(item))))
    return AdmittedResolution(target, ordered, ordered[0])


def validate_connected_peer(peer: str, resolution: AdmittedResolution) -> IPAddress:
    address = validate_public_ip(peer)
    if address not in resolution.addresses:
        raise TargetRejected("connected peer was not present in admitted DNS answers")
    return address


class SystemResolver:
    async def resolve(self, target: CollectionURL) -> tuple[str, ...]:
        loop = asyncio.get_running_loop()
        try:
            answers = await loop.getaddrinfo(
                target.host,
                target.port,
                type=0,
                proto=0,
            )
        except OSError as exc:
            raise TargetRejected("target DNS resolution failed") from exc
        return tuple(str(answer[4][0]) for answer in answers)
