"""Read-only witness for the admitted Celo RPC and facilitator capabilities."""

from __future__ import annotations

import json
import re

import httpx

from sne_sec_celo.payments import CELO_MAINNET_CAIP2, CELO_MAINNET_CHAIN_ID
from sne_sec_celo.x402_runtime import CELO_FACILITATOR_URL, CELO_RPC_URL

_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")


def main() -> None:
    with httpx.Client(timeout=15, trust_env=False, follow_redirects=False) as client:
        health_response = client.get(f"{CELO_FACILITATOR_URL}/health")
        supported_response = client.get(f"{CELO_FACILITATOR_URL}/supported")
        chain_response = client.post(
            CELO_RPC_URL,
            json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []},
        )
        latest_response = client.post(
            CELO_RPC_URL,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "eth_getBlockByNumber",
                "params": ["latest", False],
            },
        )
        finalized_response = client.post(
            CELO_RPC_URL,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "eth_getBlockByNumber",
                "params": ["finalized", False],
            },
        )
    for response in (
        health_response,
        supported_response,
        chain_response,
        latest_response,
        finalized_response,
    ):
        response.raise_for_status()

    health = health_response.json()
    supported = supported_response.json()
    chain = chain_response.json()
    latest = latest_response.json()
    finalized = finalized_response.json()
    if not isinstance(health, dict) or health.get("status") != "ok":
        raise RuntimeError("Celo facilitator health is not admitted")
    kinds = supported.get("kinds") if isinstance(supported, dict) else None
    if not isinstance(kinds, list) or not any(
        isinstance(item, dict)
        and item.get("x402Version") == 2
        and item.get("scheme") == "exact"
        and item.get("network") == CELO_MAINNET_CAIP2
        for item in kinds
    ):
        raise RuntimeError("Celo facilitator does not advertise the admitted x402 kind")
    chain_id = chain.get("result") if isinstance(chain, dict) else None
    if not isinstance(chain_id, str) or int(chain_id, 16) != CELO_MAINNET_CHAIN_ID:
        raise RuntimeError("Celo RPC chain identity differs from policy")
    latest_block = latest.get("result") if isinstance(latest, dict) else None
    finalized_block = finalized.get("result") if isinstance(finalized, dict) else None
    if not isinstance(latest_block, dict) or not isinstance(finalized_block, dict):
        raise RuntimeError("Celo RPC returned no finalized block")
    latest_number = latest_block.get("number")
    latest_hash = latest_block.get("hash")
    finalized_number = finalized_block.get("number")
    finalized_hash = finalized_block.get("hash")
    if (
        not isinstance(latest_number, str)
        or int(latest_number, 16) < 1
        or not isinstance(latest_hash, str)
        or not _HASH.fullmatch(latest_hash)
        or not isinstance(finalized_number, str)
        or int(finalized_number, 16) < 1
        or not isinstance(finalized_hash, str)
        or not _HASH.fullmatch(finalized_hash)
        or int(finalized_number, 16) > int(latest_number, 16)
    ):
        raise RuntimeError("Celo finalized block identity is malformed")

    print(
        json.dumps(
            {
                "status": "PASS",
                "effect": "READ_ONLY",
                "network": CELO_MAINNET_CAIP2,
                "chain_id": CELO_MAINNET_CHAIN_ID,
                "facilitator": "HEALTHY_X402_V2_EXACT",
                "latest_block_number": int(latest_number, 16),
                "latest_block_hash": latest_hash.lower(),
                "finalized_block_number": int(finalized_number, 16),
                "finalized_block_hash": finalized_hash.lower(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
