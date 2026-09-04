"""ERC-8004 registration file and public capability declarations."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .errors import InvariantViolation

CELO_CHAIN_ID = 42220
CELO_CAIP2 = "eip155:42220"
CELO_IDENTITY_REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432"
ERC8004_REGISTRATION_TYPE = "https://eips.ethereum.org/EIPS/eip-8004#registration-v1"
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


@dataclass(frozen=True)
class AgentSettings:
    public_base_url: str
    wallet_address: str | None = None
    agent_id: int | None = None
    x402_enabled: bool = False

    def __post_init__(self) -> None:
        base = self.public_base_url.rstrip("/")
        parsed = urlsplit(base)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise InvariantViolation("agent public base URL must be absolute HTTP(S)")
        if parsed.path or parsed.query or parsed.fragment or parsed.username is not None:
            raise InvariantViolation("agent public base URL must contain only scheme and authority")
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1"}:
            raise InvariantViolation("a non-local agent public base URL must use HTTPS")
        if self.wallet_address is not None and not _ADDRESS.fullmatch(self.wallet_address):
            raise InvariantViolation("agent wallet address must be a 20-byte EVM address")
        if self.agent_id is not None and self.agent_id < 0:
            raise InvariantViolation("ERC-8004 agent ID cannot be negative")
        if self.agent_id is not None and self.wallet_address is None:
            raise InvariantViolation("registered ERC-8004 identity requires its wallet address")
        if self.x402_enabled and self.wallet_address is None:
            raise InvariantViolation("enabled x402 requires the dedicated agent wallet address")
        object.__setattr__(self, "public_base_url", base)

    @classmethod
    def from_environment(cls) -> AgentSettings:
        agent_id_value = os.environ.get("SNE_SEC_CELO_ERC8004_AGENT_ID")
        x402_value = os.environ.get("SNE_SEC_CELO_X402_ENABLED", "false").strip().lower()
        if x402_value not in {"true", "false"}:
            raise InvariantViolation("SNE_SEC_CELO_X402_ENABLED must be true or false")
        try:
            agent_id = int(agent_id_value) if agent_id_value else None
        except ValueError as exc:
            raise InvariantViolation("ERC-8004 agent ID must be an integer") from exc
        return cls(
            public_base_url=os.environ.get(
                "SNE_SEC_CELO_PUBLIC_BASE_URL", "http://localhost:8000"
            ),
            wallet_address=os.environ.get("SNE_SEC_CELO_AGENT_WALLET"),
            agent_id=agent_id,
            x402_enabled=x402_value == "true",
        )

    @property
    def agent_uri(self) -> str:
        return f"{self.public_base_url}/.well-known/agent.json"

    @property
    def registry_identity(self) -> str:
        return f"eip155:{CELO_CHAIN_ID}:{CELO_IDENTITY_REGISTRY}"


def build_registration_file(settings: AgentSettings) -> dict[str, object]:
    services: list[dict[str, str]] = [
        {
            "name": "web",
            "endpoint": f"{settings.public_base_url}/",
            "version": "1.0.0",
        },
        {
            "name": "SNE-SEC Evidence Review API",
            "endpoint": f"{settings.public_base_url}/openapi.json",
            "version": "v1",
        },
    ]
    if settings.wallet_address is not None:
        services.append(
            {
                "name": "wallet",
                "endpoint": f"{CELO_CAIP2}:{settings.wallet_address}",
                "version": "CAIP-10",
            }
        )
    registrations: list[dict[str, object]] = []
    if settings.agent_id is not None:
        registrations.append(
            {
                "agentId": settings.agent_id,
                "agentRegistry": settings.registry_identity,
            }
        )
    return {
        "type": ERC8004_REGISTRATION_TYPE,
        "name": "SNE-SEC Celo Agent",
        "description": (
            "Evidence-backed security assessments with independently admitted settlement, "
            "immutable Reviews, remediation, rescan, and ReviewDiff."
        ),
        "image": f"{settings.public_base_url}/assets/sne-sec-celo-agent.svg",
        "services": services,
        "x402Support": settings.x402_enabled,
        "active": True,
        "registrations": registrations,
        "supportedTrust": [],
    }


def build_capabilities(settings: AgentSettings) -> dict[str, object]:
    return {
        "schema_version": "sne-sec-celo-capabilities-v1",
        "agent_uri": settings.agent_uri,
        "network": CELO_CAIP2,
        "erc8004": {
            "identity_registry": CELO_IDENTITY_REGISTRY,
            "agent_id": settings.agent_id,
            "registered": settings.agent_id is not None,
        },
        "wallet": settings.wallet_address,
        "x402": {"enabled": settings.x402_enabled},
        "assessment": {
            "reference_provider": True,
            "private_provider_required": False,
            "operations": ["create_review", "get_review", "create_review_diff"],
            "acquisition": "PASSIVE_LOW_IMPACT",
        },
    }


AGENT_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"
role="img" aria-labelledby="title desc">
<title id="title">SNE-SEC Celo Agent</title>
<desc id="desc">An evidence chain enclosed in a security shield.</desc>
<rect width="512" height="512" rx="88" fill="#0b0f0d"/>
<path d="M256 72 416 132v116c0 96-61 158-160 196C157 406 96 344 96 248V132z" fill="#35d07f"/>
<path d="M256 116 374 160v88c0 70-41 119-118 151-77-32-118-81-118-151v-88z" fill="#0b0f0d"/>
<circle cx="205" cy="220" r="30" fill="#35d07f"/>
<circle cx="307" cy="292" r="30" fill="#35d07f"/>
<path d="M226 239l60 35" stroke="#35d07f" stroke-width="22" stroke-linecap="round"/>
</svg>"""
