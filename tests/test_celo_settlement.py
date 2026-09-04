from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sne_sec_celo.canonical import digest
from sne_sec_celo.celo_settlement import (
    ERC20_TRANSFER_TOPIC,
    TRANSFER_WITH_AUTHORIZATION_SELECTOR,
    CeloSettlementVerifier,
)
from sne_sec_celo.errors import InvariantViolation
from sne_sec_celo.payment_store import SQLitePaymentStore
from sne_sec_celo.payments import (
    CELO_MAINNET_CAIP2,
    CELO_MAINNET_USDC,
    FacilitatorSettlementClaim,
    PaymentIntent,
    build_facilitator_claim,
    build_payment_intent,
    reconcile_settlement,
)

PAYER = "0x1111111111111111111111111111111111111111"
PAYEE = "0x2222222222222222222222222222222222222222"
NONCE = "0x" + ("33" * 32)
TX_HASH = "0x" + ("aa" * 32)
BLOCK_HASH = "0x" + ("bb" * 32)
NOW = datetime(2026, 9, 4, 15, 0, tzinfo=UTC)
SOURCE_CONFIGURATION_DIGEST = digest({"source": "deterministic-test-rpc"})


def _word(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _address_word(value: str) -> bytes:
    return bytes(12) + bytes.fromhex(value[2:])


def authorization_input(*, nonce: str = NONCE) -> str:
    words = (
        _address_word(PAYER),
        _address_word(PAYEE),
        _word(10_000),
        _word(0),
        _word(2_000_000_000),
        bytes.fromhex(nonce[2:]),
        _word(27),
        bytes(32),
        bytes(32),
    )
    return "0x" + TRANSFER_WITH_AUTHORIZATION_SELECTOR + b"".join(words).hex()


def transfer_log(*, index: int = 4) -> dict[str, object]:
    return {
        "address": CELO_MAINNET_USDC,
        "topics": [
            ERC20_TRANSFER_TOPIC,
            "0x" + ("0" * 24) + PAYER[2:],
            "0x" + ("0" * 24) + PAYEE[2:],
        ],
        "data": "0x" + _word(10_000).hex(),
        "logIndex": hex(index),
        "transactionHash": TX_HASH,
        "blockHash": BLOCK_HASH,
        "removed": False,
    }


def intent(*, resource: str = "/v1/x402/reviews/review_1") -> PaymentIntent:
    return build_payment_intent(
        resource=resource,
        network=CELO_MAINNET_CAIP2,
        asset=CELO_MAINNET_USDC,
        amount_atomic=10_000,
        payer=PAYER,
        payee=PAYEE,
        nonce=NONCE,
        valid_after=0,
        valid_before=2_000_000_000,
        created_at=NOW,
    )


class FakeRPC:
    def __init__(self, *, logs: list[dict[str, object]] | None = None) -> None:
        self.logs = logs if logs is not None else [transfer_log()]
        self.input = authorization_input()
        self.chain_id = hex(42220)
        self.policy_head_number = 120
        self.canonical_hash = BLOCK_HASH

    async def call(self, method: str, params: list[Any]) -> Any:
        if method == "eth_chainId":
            return self.chain_id
        if method == "eth_getTransactionReceipt":
            return {
                "transactionHash": TX_HASH,
                "status": "0x1",
                "blockNumber": "0x64",
                "blockHash": BLOCK_HASH,
                "logs": self.logs,
            }
        if method == "eth_getTransactionByHash":
            return {
                "hash": TX_HASH,
                "to": CELO_MAINNET_USDC,
                "input": self.input,
                "blockNumber": "0x64",
                "blockHash": BLOCK_HASH,
            }
        if method == "eth_getBlockByNumber" and params[0] == "latest":
            return {"number": hex(self.policy_head_number), "hash": "0x" + ("cc" * 32)}
        if method == "eth_getBlockByNumber" and params[0] == "0x64":
            return {"number": "0x64", "hash": self.canonical_hash}
        raise AssertionError(f"unexpected RPC call: {method} {params}")


def claim(payment_intent: PaymentIntent) -> FacilitatorSettlementClaim:
    return build_facilitator_claim(
        intent=payment_intent,
        transaction_hash=TX_HASH,
        network=CELO_MAINNET_CAIP2,
        payer=PAYER,
        amount_atomic=10_000,
        claimed_at=NOW + timedelta(seconds=1),
    )


class CeloSettlementTests(unittest.IsolatedAsyncioTestCase):
    async def test_admits_one_direct_canonical_confirmed_transfer(self) -> None:
        payment_intent = intent()
        payment_claim = claim(payment_intent)
        observation = await CeloSettlementVerifier(
            FakeRPC(), source_configuration_digest=SOURCE_CONFIGURATION_DIGEST
        ).verify(
            intent=payment_intent,
            claim=payment_claim,
            observed_at=NOW + timedelta(seconds=2),
        )

        self.assertEqual(observation.transaction_hash, TX_HASH)
        self.assertEqual(observation.log_index, 4)
        self.assertEqual(observation.confirmations, 21)
        self.assertEqual(observation.authorization_id, payment_intent.authorization_id)

    async def test_rejects_multiple_exact_transfer_logs_as_ambiguous(self) -> None:
        payment_intent = intent()
        rpc = FakeRPC(logs=[transfer_log(index=4), transfer_log(index=5)])
        with self.assertRaisesRegex(InvariantViolation, "absent or ambiguous"):
            await CeloSettlementVerifier(
                rpc, source_configuration_digest=SOURCE_CONFIGURATION_DIGEST
            ).verify(
                intent=payment_intent,
                claim=claim(payment_intent),
                observed_at=NOW,
            )

    async def test_rejects_another_authorization_or_insufficient_confirmation_head(self) -> None:
        payment_intent = intent()
        rpc = FakeRPC()
        rpc.input = authorization_input(nonce="0x" + ("44" * 32))
        with self.assertRaisesRegex(InvariantViolation, "nonce differs"):
            await CeloSettlementVerifier(
                rpc, source_configuration_digest=SOURCE_CONFIGURATION_DIGEST
            ).verify(
                intent=payment_intent,
                claim=claim(payment_intent),
                observed_at=NOW,
            )

        rpc = FakeRPC()
        rpc.policy_head_number = 99
        with self.assertRaisesRegex(InvariantViolation, "above the confirmation policy head"):
            await CeloSettlementVerifier(
                rpc, source_configuration_digest=SOURCE_CONFIGURATION_DIGEST
            ).verify(
                intent=payment_intent,
                claim=claim(payment_intent),
                observed_at=NOW,
            )

    async def test_append_only_store_is_idempotent_but_rejects_replay_conflict(self) -> None:
        payment_intent = intent()
        payment_claim = claim(payment_intent)
        observation = await CeloSettlementVerifier(
            FakeRPC(), source_configuration_digest=SOURCE_CONFIGURATION_DIGEST
        ).verify(
            intent=payment_intent,
            claim=payment_claim,
            observed_at=NOW + timedelta(seconds=2),
        )
        settlement = reconcile_settlement(
            intent=payment_intent,
            claim=payment_claim,
            observation=observation,
            settled_at=NOW + timedelta(seconds=3),
        )
        with tempfile.TemporaryDirectory() as directory:
            store = SQLitePaymentStore(Path(directory) / "payments.sqlite3")
            store.initialize()
            store.record_intent(payment_intent)
            store.record_claim(payment_claim)
            store.admit_settlement(observation, settlement)
            store.record_intent(payment_intent)
            store.record_claim(payment_claim)
            store.admit_settlement(observation, settlement)
            restored = store.settlement_for_transaction(TX_HASH)
            self.assertEqual(restored, settlement)

            with self.assertRaisesRegex(InvariantViolation, "replay conflicts"):
                store.record_intent(intent(resource="/v1/x402/reviews/review_2"))

            connection = sqlite3.connect(store.database_path)
            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "UPDATE payment_settlements SET external_event_id = 'changed'"
                    )
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
