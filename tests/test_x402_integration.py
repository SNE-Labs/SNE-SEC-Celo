from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from httpx import ASGITransport, AsyncClient
from x402.http import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    decode_payment_required_header,
    encode_payment_signature_header,
)
from x402.schemas import (
    PaymentPayload,
    PaymentRequirements,
    SettleResponse,
    SupportedKind,
    SupportedResponse,
    VerifyResponse,
)

from sne_sec_celo.agent import AgentSettings
from sne_sec_celo.api import create_app
from sne_sec_celo.payment_store import SQLitePaymentStore
from sne_sec_celo.payments import (
    CELO_MAINNET_CAIP2,
    authorization_identity,
)
from sne_sec_celo.store import SQLiteReviewStore
from sne_sec_celo.x402_runtime import X402Settings, build_x402_runtime
from tests.helpers import SequenceClock, exchange, provider
from tests.test_celo_settlement import NONCE, PAYEE, PAYER, TX_HASH, FakeRPC


class FakeFacilitator:
    def __init__(self, store: SQLitePaymentStore) -> None:
        self.store = store
        self.settle_calls = 0
        self.verify_valid = True

    def get_supported(self) -> SupportedResponse:
        return SupportedResponse(
            kinds=[
                SupportedKind(
                    x402_version=2,
                    scheme="exact",
                    network=CELO_MAINNET_CAIP2,
                    extra={},
                )
            ],
            extensions=[],
            signers={CELO_MAINNET_CAIP2: ["0x" + ("55" * 20)]},
        )

    async def verify(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> VerifyResponse:
        return VerifyResponse(
            is_valid=self.verify_valid,
            invalid_reason=None if self.verify_valid else "authorization_already_used",
            payer=PAYER,
        )

    async def settle(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> SettleResponse:
        authorization = payload.payload["authorization"]
        assert isinstance(authorization, dict)
        authorization_id = authorization_identity(
            network=str(requirements.network),
            asset=requirements.asset,
            payer=str(authorization["from"]),
            nonce=str(authorization["nonce"]),
        )
        self.store.get_intent_by_authorization(authorization_id)
        self.settle_calls += 1
        return SettleResponse(
            success=True,
            transaction=TX_HASH,
            network=CELO_MAINNET_CAIP2,
            payer=PAYER,
            amount="10000",
        )


def payment_payload(requirements: PaymentRequirements) -> PaymentPayload:
    return PaymentPayload(
        x402_version=2,
        accepted=requirements,
        payload={
            "authorization": {
                "from": PAYER,
                "to": PAYEE,
                "value": "10000",
                "validAfter": "0",
                "validBefore": "2000000000",
                "nonce": NONCE,
            },
            "signature": "0x00",
        },
    )


class X402IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_402_then_delivery_only_after_independent_celo_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "reviews.sqlite3"
            review = await provider(exchange()).assess("example.org")
            review_store = SQLiteReviewStore(database)
            review_store.initialize()
            review_store.add(review)

            payment_store = SQLitePaymentStore(database)
            payment_store.initialize()
            facilitator = FakeFacilitator(payment_store)
            settings = X402Settings(enabled=True, pay_to=PAYEE)
            runtime = build_x402_runtime(
                settings=settings,
                store=payment_store,
                facilitator=facilitator,
                rpc=FakeRPC(),
                clock=SequenceClock(),
            )
            app = create_app(
                database_path=database,
                agent_settings=AgentSettings(
                    public_base_url="https://agent.example.org",
                    wallet_address=PAYEE,
                    x402_enabled=True,
                ),
                x402_settings=settings,
                x402_runtime=runtime,
            )
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                unpaid = await client.get(f"/v1/x402/reviews/{review.review_id}")
                self.assertEqual(unpaid.status_code, 402)
                requirement = decode_payment_required_header(
                    unpaid.headers[PAYMENT_REQUIRED_HEADER]
                ).accepts[0]
                paid = await client.get(
                    f"/v1/x402/reviews/{review.review_id}",
                    headers={
                        "PAYMENT-SIGNATURE": encode_payment_signature_header(
                            payment_payload(requirement)
                        )
                    },
                )

            self.assertEqual(paid.status_code, 200)
            self.assertEqual(paid.json()["result_digest"], review.result_digest)
            self.assertIn(PAYMENT_RESPONSE_HEADER, paid.headers)
            self.assertEqual(facilitator.settle_calls, 1)
            self.assertIsNotNone(payment_store.settlement_for_transaction(TX_HASH))

    async def test_ambiguous_effect_fails_closed_then_recovers_without_resettling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "reviews.sqlite3"
            review = await provider(exchange()).assess("example.org")
            review_store = SQLiteReviewStore(database)
            review_store.initialize()
            review_store.add(review)
            payment_store = SQLitePaymentStore(database)
            payment_store.initialize()
            facilitator = FakeFacilitator(payment_store)
            rpc = FakeRPC()
            rpc.chain_id = "0x1"
            settings = X402Settings(enabled=True, pay_to=PAYEE)
            runtime = build_x402_runtime(
                settings=settings,
                store=payment_store,
                facilitator=facilitator,
                rpc=rpc,
                clock=SequenceClock(),
            )
            app = create_app(
                database_path=database,
                agent_settings=AgentSettings(
                    public_base_url="https://agent.example.org",
                    wallet_address=PAYEE,
                    x402_enabled=True,
                ),
                x402_settings=settings,
                x402_runtime=runtime,
            )
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                unpaid = await client.get(f"/v1/x402/reviews/{review.review_id}")
                requirement = decode_payment_required_header(
                    unpaid.headers[PAYMENT_REQUIRED_HEADER]
                ).accepts[0]
                response = await client.get(
                    f"/v1/x402/reviews/{review.review_id}",
                    headers={
                        "PAYMENT-SIGNATURE": encode_payment_signature_header(
                            payment_payload(requirement)
                        )
                    },
                )
                self.assertEqual(response.status_code, 402)
                self.assertIsNone(payment_store.settlement_for_transaction(TX_HASH))

                rpc.chain_id = hex(42220)
                facilitator.verify_valid = False
                recovered = await client.get(
                    f"/v1/x402/reviews/{review.review_id}",
                    headers={
                        "PAYMENT-SIGNATURE": encode_payment_signature_header(
                            payment_payload(requirement)
                        )
                    },
                )

            self.assertEqual(recovered.status_code, 200)
            self.assertEqual(recovered.json()["result_digest"], review.result_digest)
            self.assertEqual(facilitator.settle_calls, 1)
            self.assertIsNotNone(payment_store.settlement_for_transaction(TX_HASH))


if __name__ == "__main__":
    unittest.main()
