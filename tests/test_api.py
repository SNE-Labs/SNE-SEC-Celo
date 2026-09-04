from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from httpx import ASGITransport, AsyncClient

from sne_sec_celo.agent import CELO_IDENTITY_REGISTRY, AgentSettings
from sne_sec_celo.api import create_app
from sne_sec_celo.errors import InvariantViolation
from sne_sec_celo.store import SQLiteReviewStore
from sne_sec_celo.x402_runtime import X402Settings
from tests.helpers import exchange, provider


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

    async def test_x402_payment_destination_can_be_the_operator_treasury(self) -> None:
        agent = AgentSettings(
            public_base_url="https://agent.example.org",
            wallet_address="0x1111111111111111111111111111111111111111",
            x402_enabled=True,
        )
        with patch.dict(
            "os.environ",
            {
                "SNE_SEC_CELO_X402_PAY_TO": (
                    "0x34385Fc3B012Ae8980e17F6c3224a5aE0f946289"
                )
            },
            clear=True,
        ):
            payment = X402Settings.from_environment(agent)
        self.assertEqual(
            payment.pay_to,
            "0x34385fc3b012ae8980e17f6c3224a5ae0f946289",
        )
        self.assertEqual(payment.amount_atomic, 1_000_000)
        self.assertNotEqual(payment.pay_to, agent.wallet_address)

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

    async def test_public_projection_and_single_fixed_full_example(self) -> None:
        assessment = provider(
            exchange(),
            exchange(
                headers=(
                    ("strict-transport-security", "present"),
                    ("content-security-policy", "present"),
                    ("x-content-type-options", "present"),
                    ("referrer-policy", "present"),
                    ("permissions-policy", "present"),
                )
            ),
        )
        example = await assessment.assess("example.org")
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "reviews.sqlite3"
            store = SQLiteReviewStore(database)
            store.initialize()
            store.add(example)
            app = create_app(
                database_path=database,
                assessment_provider=assessment,
                public_example_review_id=example.review_id,
            )
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                created = await client.post(
                    "/v1/reference/reviews", json={"target": "example.org"}
                )
                review_id = created.json()["review_id"]
                preview = await client.get(f"/v1/reviews/{review_id}")
                public_example = await client.get("/v1/reference/example-review")
                comparison = await client.post(
                    "/v1/review-diffs",
                    json={
                        "previous_review_id": example.review_id,
                        "current_review_id": review_id,
                    },
                )
                commerce = await client.get("/.well-known/sne-sec-commerce.json")

        preview_keys = {"review_id", "status", "score", "summary"}
        self.assertEqual(created.status_code, 201)
        self.assertEqual(set(created.json()), preview_keys)
        self.assertEqual(preview.status_code, 200)
        self.assertEqual(set(preview.json()), preview_keys)
        self.assertEqual(preview.json(), created.json())
        self.assertNotIn("findings", preview.text)
        self.assertNotIn("evidence", preview.text)
        self.assertNotIn("remediation", preview.text)

        self.assertEqual(public_example.status_code, 200)
        self.assertEqual(public_example.json()["review_id"], example.review_id)
        self.assertIn("evidence", public_example.json())
        self.assertIn("findings", public_example.json())

        self.assertEqual(comparison.status_code, 200)
        self.assertEqual(
            set(comparison.json()),
            {"previous_review_id", "current_review_id", "status", "summary"},
        )
        self.assertNotIn("entries", comparison.text)
        self.assertNotIn("rule_id", comparison.text)
        self.assertNotIn("diff_digest", comparison.text)

        policy = commerce.json()
        self.assertEqual(
            policy["public"]["fixed_example_review"]["review_id"],
            example.review_id,
        )
        self.assertEqual(policy["x402"]["full_review"]["amount_atomic"], "1000000")
        self.assertEqual(
            policy["x402"]["full_review_diff"]["amount_atomic"], "1000000"
        )
        self.assertFalse(policy["x402"]["full_review"]["available"])

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
