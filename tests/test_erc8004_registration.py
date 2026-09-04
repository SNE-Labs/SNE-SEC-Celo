from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import rlp
from eth_keys import keys
from eth_utils import keccak

from sne_sec_celo.erc8004_registration import (
    CELO_IDENTITY_REGISTRY,
    CELO_MAINNET_USDT,
    CELO_USDT_FEE_ADAPTER,
    REGISTERED_TOPIC,
    TRANSFER_TOPIC,
    BroadcastUncertain,
    RegistrationTransaction,
    SignedRegistration,
    broadcast_registration,
    encode_register_call,
    reconcile_registration,
    sign_cip64,
)
from sne_sec_celo.operational_provisioning import OperationalSecretVault

PRIVATE_KEY = "0x" + "0" * 63 + "1"
AGENT = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
URI = "https://agent.example/.well-known/agent.json"


class FakeRegistrationRPC:
    def __init__(self, *, uncertain: bool = False) -> None:
        self.uncertain = uncertain
        self.send_calls = 0
        self.sent_hash: str | None = None
        self.mined = False
        self.transaction_data = encode_register_call(URI)

    def chain_id(self) -> int:
        return 42220

    def block_number(self) -> int:
        return 102 if self.mined else 100

    def code(self, _address: str) -> str:
        return "0x6000"

    def token_decimals(self, _token: str) -> int:
        return 6

    def fee_currencies(self) -> tuple[str, ...]:
        return (CELO_USDT_FEE_ADAPTER,)

    def adapted_token(self, _caller: str) -> str:
        return CELO_MAINNET_USDT

    def token_balance(self, token: str, _address: str) -> int:
        if token == CELO_USDT_FEE_ADAPTER:
            return 20_000 * 10**12
        return 20_000 if token == CELO_MAINNET_USDT else 0

    def nonce(self, _address: str) -> int:
        return 0

    def estimate(self, _transaction: RegistrationTransaction) -> int:
        return 200_000

    def fee_gas_price(self) -> int:
        return 10_000_000_000

    def send(self, signed: SignedRegistration) -> str:
        self.send_calls += 1
        self.sent_hash = signed.transaction_hash
        if self.uncertain:
            raise BroadcastUncertain("timeout")
        return self.sent_hash

    def transaction(self, tx_hash: str) -> dict[str, object] | None:
        if not self.mined or tx_hash != self.sent_hash:
            return None
        return {
            "from": AGENT,
            "to": CELO_IDENTITY_REGISTRY,
            "nonce": "0x0",
            "input": self.transaction_data,
            "feeCurrency": CELO_USDT_FEE_ADAPTER,
        }

    def receipt(self, tx_hash: str) -> dict[str, object] | None:
        if not self.mined or tx_hash != self.sent_hash:
            return None
        owner = "0x" + AGENT[2:].rjust(64, "0")
        agent_id = "0x" + hex(123)[2:].rjust(64, "0")
        zero = "0x" + "0" * 64
        return {
            "status": "0x1",
            "blockNumber": "0x65",
            "blockHash": "0x" + "ab" * 32,
            "gasUsed": "0x30d40",
            "effectiveGasPrice": "0x2540be400",
            "logs": [
                {
                    "address": CELO_IDENTITY_REGISTRY,
                    "topics": [TRANSFER_TOPIC, zero, owner, agent_id],
                },
                {
                    "address": CELO_IDENTITY_REGISTRY,
                    "topics": [REGISTERED_TOPIC, agent_id, owner],
                },
            ],
        }

    def block(self, number: int) -> dict[str, object]:
        assert number == 101
        return {"hash": "0x" + "ab" * 32}

    def owner_of(self, agent_id: int) -> str:
        assert agent_id == 123
        return AGENT

    def token_uri(self, agent_id: int) -> str:
        assert agent_id == 123
        return URI


class ERC8004RegistrationTests(unittest.TestCase):
    def vault(self, root: str) -> OperationalSecretVault:
        vault = OperationalSecretVault(
            Path(root) / "vault.dpapi",
            protect=lambda value: b"sealed:" + value,
            unprotect=lambda value: value.removeprefix(b"sealed:"),
        )
        vault.save(
            {
                "format": "sne-sec-celo-operational-secrets-v1",
                "identity": {
                    "wallet_address": AGENT,
                    "wallet_private_key": PRIVATE_KEY,
                },
            }
        )
        return vault

    def test_register_call_is_bounded_https_abi(self) -> None:
        encoded = encode_register_call(URI)
        self.assertTrue(encoded.startswith("0xf2c298be"))
        self.assertIn(URI.encode().hex(), encoded)
        with self.assertRaisesRegex(Exception, "HTTPS"):
            encode_register_call("http://agent.example/agent.json")

    def test_cip64_signature_recovers_agent_wallet(self) -> None:
        transaction = RegistrationTransaction(
            source=AGENT,
            agent_uri=URI,
            nonce=0,
            gas_limit=250_000,
            max_fee_per_gas=20_000_000_000,
        )
        signed = sign_cip64(transaction, PRIVATE_KEY)
        self.assertEqual(signed.raw_transaction[0], 0x7B)
        decoded = rlp.decode(signed.raw_transaction[1:])
        signing_hash = keccak(b"\x7b" + rlp.encode(decoded[:10]))
        signature = keys.Signature(
            vrs=(
                int.from_bytes(decoded[10], "big"),
                int.from_bytes(decoded[11], "big"),
                int.from_bytes(decoded[12], "big"),
            )
        )
        self.assertEqual(
            signature.recover_public_key_from_msg_hash(signing_hash).to_checksum_address().lower(),
            AGENT,
        )
        self.assertEqual(signed.transaction_hash, "0x" + keccak(signed.raw_transaction).hex())

    def test_registration_is_persisted_broadcast_once_and_reconciled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            vault = self.vault(temporary)
            rpc = FakeRegistrationRPC()
            broadcast = broadcast_registration(vault=vault, rpc=rpc, agent_uri=URI)  # type: ignore[arg-type]
            self.assertEqual(broadcast["state"], "BROADCAST_ACCEPTED")
            self.assertEqual(rpc.send_calls, 1)
            persisted = vault.load()["identity"]
            assert isinstance(persisted, dict)
            self.assertNotIn("raw_transaction", str(persisted))
            self.assertNotIn(PRIVATE_KEY, str(broadcast))

            rpc.mined = True
            reconciled = reconcile_registration(vault=vault, rpc=rpc)  # type: ignore[arg-type]
            self.assertEqual(reconciled["state"], "RECONCILED")
            self.assertEqual(reconciled["agent_id"], 123)
            self.assertEqual(reconciled["fee_usdt_atomic"], 2_000)
            self.assertEqual(rpc.send_calls, 1)

    def test_uncertain_broadcast_is_never_retried(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            vault = self.vault(temporary)
            rpc = FakeRegistrationRPC(uncertain=True)
            first = broadcast_registration(vault=vault, rpc=rpc, agent_uri=URI)  # type: ignore[arg-type]
            second = broadcast_registration(vault=vault, rpc=rpc, agent_uri=URI)  # type: ignore[arg-type]
            self.assertEqual(first["state"], "BROADCAST_UNKNOWN")
            self.assertEqual(second["outcome"], "PENDING_OR_RECONCILIATION_REQUIRED")
            self.assertEqual(rpc.send_calls, 1)


if __name__ == "__main__":
    unittest.main()
