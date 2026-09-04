from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from httpx import ASGITransport, AsyncClient

from sne_sec_celo.agent import CELO_IDENTITY_REGISTRY, AgentSettings
from sne_sec_celo.api import create_app
from sne_sec_celo.errors import InvariantViolation


class ApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_health_declares_standalone_reference_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            transport = ASGITransport(
                app=create_app(database_path=Path(directory) / "reviews.sqlite3")
            )
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get("/healthz")
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json()["private_provider_required"])
            self.assertIsNone(response.json()["x402_settlement_admission"])

    async def test_x402_cannot_be_advertised_without_dedicated_wallet(self) -> None:
        with self.assertRaisesRegex(InvariantViolation, "dedicated agent wallet"):
            AgentSettings(
                public_base_url="https://agent.example.org",
                x402_enabled=True,
            )

    async def test_private_target_is_rejected_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            transport = ASGITransport(
                app=create_app(database_path=Path(directory) / "reviews.sqlite3")
            )
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/v1/reference/reviews", json={"target": "localhost"}
                )
            self.assertEqual(response.status_code, 422)

    async def test_erc8004_registration_file_is_spec_shaped_and_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings = AgentSettings(
                public_base_url="https://agent.example.org",
                wallet_address="0x1111111111111111111111111111111111111111",
                agent_id=42,
            )
            transport = ASGITransport(
                app=create_app(
                    database_path=Path(directory) / "reviews.sqlite3",
                    agent_settings=settings,
                )
            )
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get("/.well-known/agent.json")
                capabilities = await client.get("/.well-known/sne-sec-capabilities.json")
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(
                payload["type"],
                "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
            )
            self.assertFalse(payload["x402Support"])
            self.assertEqual(
                payload["registrations"],
                [
                    {
                        "agentId": 42,
                        "agentRegistry": f"eip155:42220:{CELO_IDENTITY_REGISTRY}",
                    }
                ],
            )
            self.assertTrue(capabilities.json()["erc8004"]["registered"])


if __name__ == "__main__":
    unittest.main()
