"""Crash-aware one-shot ERC-8004 registration on Celo with CIP-64 fees."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from .agent import CELO_CHAIN_ID, CELO_IDENTITY_REGISTRY
from .canonical import canonical_json, digest
from .errors import InvariantViolation
from .operational_provisioning import OperationalSecretVault, default_vault_path
from .payments import normalize_address

CELO_RPC_URL = "https://forno.celo.org"
CELO_MAINNET_USDT = "0x48065fbbe25f71c9282ddf5e1cd6d6a887483d5e"
CELO_USDT_FEE_ADAPTER = "0x0e2a3e05bc9a16f5292a6170456a710cb89c6f72"
CELO_FEE_CURRENCY_DIRECTORY = "0x15f344b9e6c3cb6f0376a36a64928b13f62c6276"
REGISTER_SELECTOR = "f2c298be"
BALANCE_OF_SELECTOR = "70a08231"
DECIMALS_SELECTOR = "313ce567"
GET_CURRENCIES_SELECTOR = "61c661de"
ADAPTED_TOKEN_SELECTOR = "989516db"
WRAPPED_TOKEN_SELECTOR = "996c6cc3"
OWNER_OF_SELECTOR = "6352211e"
TOKEN_URI_SELECTOR = "c87b56dd"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
REGISTERED_TOPIC = "0xca52e62c367d81bb2e328eb795f7c7ba24afb478408a26c0e201d155c449bc4a"
REGISTRATION_RECORD = "erc8004_registration"
GAS_MARGIN_BPS = 2_500
MAX_FEE_USDT_ATOMIC = 10_000
USDT_SCALE = 10**12


class BroadcastUncertain(InvariantViolation):
    """The RPC result cannot prove whether a submitted transaction was accepted."""


def _quantity(value: object, label: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise InvariantViolation(f"malformed RPC {label}")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise InvariantViolation(f"malformed RPC {label}") from exc


def _address_word(address: str) -> str:
    return normalize_address(address)[2:].rjust(64, "0")


def _uint_word(value: int) -> str:
    if value < 0 or value >= 2**256:
        raise InvariantViolation("ABI integer is outside uint256")
    return hex(value)[2:].rjust(64, "0")


def encode_register_call(agent_uri: str) -> str:
    encoded = agent_uri.encode("utf-8")
    if not agent_uri.startswith("https://") or len(encoded) > 2_048:
        raise InvariantViolation("ERC-8004 agent URI must be a bounded HTTPS URL")
    padding = b"\x00" * ((32 - len(encoded) % 32) % 32)
    return "0x" + REGISTER_SELECTOR + _uint_word(32) + _uint_word(len(encoded)) + (
        encoded + padding
    ).hex()


def _decode_abi_string(value: str) -> str:
    try:
        data = bytes.fromhex(value.removeprefix("0x"))
        offset = int.from_bytes(data[:32], "big")
        length = int.from_bytes(data[offset : offset + 32], "big")
        end = offset + 32 + length
        if offset % 32 or end > len(data) or length > 2_048:
            raise ValueError
        return data[offset + 32 : end].decode("utf-8")
    except (UnicodeDecodeError, ValueError, OverflowError) as exc:
        raise InvariantViolation("malformed ABI string") from exc


@dataclass(frozen=True)
class RegistrationTransaction:
    source: str
    agent_uri: str
    nonce: int
    gas_limit: int
    max_fee_per_gas: int
    max_priority_fee_per_gas: int = 0
    chain_id: int = CELO_CHAIN_ID
    registry: str = CELO_IDENTITY_REGISTRY
    fee_currency: str = CELO_USDT_FEE_ADAPTER

    def __post_init__(self) -> None:
        for field in ("source", "registry", "fee_currency"):
            object.__setattr__(self, field, normalize_address(str(getattr(self, field))))
        encode_register_call(self.agent_uri)
        if self.chain_id != CELO_CHAIN_ID or min(
            self.nonce,
            self.gas_limit,
            self.max_fee_per_gas,
            self.max_priority_fee_per_gas,
        ) < 0:
            raise InvariantViolation("invalid ERC-8004 transaction quantities")
        if self.max_priority_fee_per_gas > self.max_fee_per_gas:
            raise InvariantViolation("priority fee exceeds maximum fee")

    @property
    def data(self) -> str:
        return encode_register_call(self.agent_uri)


@dataclass(frozen=True)
class SignedRegistration:
    transaction_hash: str
    raw_transaction: bytes


def sign_cip64(transaction: RegistrationTransaction, private_key: str) -> SignedRegistration:
    try:
        import rlp  # type: ignore[import-untyped]
        from eth_keys import keys  # type: ignore[attr-defined]
        from eth_utils import keccak  # type: ignore[attr-defined]
    except ImportError as exc:
        raise InvariantViolation(
            'ERC-8004 signing requires: pip install -e ".[wallet-tools]"'
        ) from exc
    try:
        key_bytes = bytes.fromhex(private_key.removeprefix("0x"))
        key = keys.PrivateKey(key_bytes)
    except (ValueError, TypeError) as exc:
        raise InvariantViolation("operational signing key is malformed") from exc
    if key.public_key.to_checksum_address().lower() != transaction.source:
        raise InvariantViolation("operational signing key does not own agent identity")
    unsigned = [
        transaction.chain_id,
        transaction.nonce,
        transaction.max_priority_fee_per_gas,
        transaction.max_fee_per_gas,
        transaction.gas_limit,
        bytes.fromhex(transaction.registry[2:]),
        0,
        bytes.fromhex(transaction.data[2:]),
        [],
        bytes.fromhex(transaction.fee_currency[2:]),
    ]
    signature = key.sign_msg_hash(keccak(b"\x7b" + rlp.encode(unsigned)))
    raw = b"\x7b" + rlp.encode([*unsigned, signature.v, signature.r, signature.s])
    return SignedRegistration("0x" + keccak(raw).hex(), raw)


class RegistrationRPC:
    def __init__(self, url: str = CELO_RPC_URL) -> None:
        if not url.startswith("https://"):
            raise InvariantViolation("Celo RPC must use HTTPS")
        self.url = url
        self.request_id = 0

    def rpc(self, method: str, params: list[object], *, broadcast: bool = False) -> Any:
        self.request_id += 1
        try:
            with httpx.Client(timeout=20, follow_redirects=False, trust_env=False) as client:
                response = client.post(
                    self.url,
                    json={
                        "jsonrpc": "2.0",
                        "id": self.request_id,
                        "method": method,
                        "params": params,
                    },
                    headers={"Accept": "application/json", "User-Agent": "sne-sec-celo/1.0"},
                )
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, OSError, ValueError) as exc:
            error = BroadcastUncertain if broadcast else InvariantViolation
            raise error(f"Celo RPC {method} result was not admitted") from exc
        if not isinstance(body, dict) or body.get("error") is not None:
            error = BroadcastUncertain if broadcast else InvariantViolation
            raise error(f"Celo RPC {method} returned an error")
        return body.get("result")

    def eth_call(self, to: str, data: str, *, caller: str | None = None) -> str:
        call = {"to": normalize_address(to), "data": data}
        if caller is not None:
            call["from"] = normalize_address(caller)
        result = self.rpc("eth_call", [call, "latest"])
        if not isinstance(result, str) or not result.startswith("0x"):
            raise InvariantViolation("malformed RPC eth_call result")
        return result

    def chain_id(self) -> int:
        return _quantity(self.rpc("eth_chainId", []), "chain ID")

    def block_number(self) -> int:
        return _quantity(self.rpc("eth_blockNumber", []), "block number")

    def nonce(self, address: str) -> int:
        return _quantity(
            self.rpc("eth_getTransactionCount", [normalize_address(address), "pending"]),
            "nonce",
        )

    def code(self, address: str) -> str:
        value = self.rpc("eth_getCode", [normalize_address(address), "latest"])
        if not isinstance(value, str) or not value.startswith("0x"):
            raise InvariantViolation("malformed contract code")
        return value

    def token_balance(self, token: str, address: str) -> int:
        return _quantity(
            self.eth_call(token, "0x" + BALANCE_OF_SELECTOR + _address_word(address)),
            "token balance",
        )

    def token_decimals(self, token: str) -> int:
        return _quantity(self.eth_call(token, "0x" + DECIMALS_SELECTOR), "token decimals")

    def fee_currencies(self) -> tuple[str, ...]:
        raw = self.eth_call(CELO_FEE_CURRENCY_DIRECTORY, "0x" + GET_CURRENCIES_SELECTOR)
        try:
            data = bytes.fromhex(raw[2:])
            offset = int.from_bytes(data[:32], "big")
            count = int.from_bytes(data[offset : offset + 32], "big")
            start = offset + 32
            end = start + count * 32
            if offset % 32 or count > 10_000 or end > len(data):
                raise ValueError
            return tuple(
                normalize_address("0x" + data[index + 12 : index + 32].hex())
                for index in range(start, end, 32)
            )
        except (ValueError, OverflowError) as exc:
            raise InvariantViolation("malformed fee currency allowlist") from exc

    def adapted_token(self, caller: str) -> str:
        try:
            raw = self.eth_call(
                CELO_USDT_FEE_ADAPTER, "0x" + ADAPTED_TOKEN_SELECTOR, caller=caller
            )
        except InvariantViolation:
            raw = self.eth_call(
                CELO_USDT_FEE_ADAPTER, "0x" + WRAPPED_TOKEN_SELECTOR, caller=caller
            )
        if len(raw) != 66:
            raise InvariantViolation("malformed adapted token")
        return normalize_address("0x" + raw[-40:])

    def fee_gas_price(self) -> int:
        return _quantity(
            self.rpc("eth_gasPrice", [CELO_USDT_FEE_ADAPTER]), "fee currency gas price"
        )

    def estimate(self, transaction: RegistrationTransaction) -> int:
        return _quantity(
            self.rpc(
                "eth_estimateGas",
                [
                    {
                        "from": transaction.source,
                        "to": transaction.registry,
                        "data": transaction.data,
                        "value": "0x0",
                        "feeCurrency": transaction.fee_currency,
                    }
                ],
            ),
            "gas estimate",
        )

    def send(self, signed: SignedRegistration) -> str:
        value = self.rpc(
            "eth_sendRawTransaction",
            ["0x" + signed.raw_transaction.hex()],
            broadcast=True,
        )
        if not isinstance(value, str) or len(value) != 66:
            raise BroadcastUncertain("Celo RPC returned a malformed transaction hash")
        return value.lower()

    def transaction(self, tx_hash: str) -> dict[str, object] | None:
        value = self.rpc("eth_getTransactionByHash", [tx_hash])
        if value is None:
            return None
        if not isinstance(value, dict):
            raise InvariantViolation("malformed Celo transaction")
        return value

    def receipt(self, tx_hash: str) -> dict[str, object] | None:
        value = self.rpc("eth_getTransactionReceipt", [tx_hash])
        if value is None:
            return None
        if not isinstance(value, dict):
            raise InvariantViolation("malformed Celo receipt")
        return value

    def block(self, number: int) -> dict[str, object]:
        value = self.rpc("eth_getBlockByNumber", [hex(number), False])
        if not isinstance(value, dict):
            raise InvariantViolation("malformed Celo block")
        return value

    def owner_of(self, agent_id: int) -> str:
        raw = self.eth_call(CELO_IDENTITY_REGISTRY, "0x" + OWNER_OF_SELECTOR + _uint_word(agent_id))
        if len(raw) != 66:
            raise InvariantViolation("malformed ERC-8004 owner")
        return normalize_address("0x" + raw[-40:])

    def token_uri(self, agent_id: int) -> str:
        return _decode_abi_string(
            self.eth_call(CELO_IDENTITY_REGISTRY, "0x" + TOKEN_URI_SELECTOR + _uint_word(agent_id))
        )


def _intent_scope(transaction: RegistrationTransaction) -> dict[str, object]:
    return {
        "operation": "ERC8004_REGISTER",
        "chain_id": transaction.chain_id,
        "source": transaction.source,
        "registry": transaction.registry,
        "agent_uri": transaction.agent_uri,
        "nonce": transaction.nonce,
        "gas_limit": transaction.gas_limit,
        "max_fee_per_gas": transaction.max_fee_per_gas,
        "max_priority_fee_per_gas": transaction.max_priority_fee_per_gas,
        "fee_currency": transaction.fee_currency,
        "maximum_fee_usdt_atomic": MAX_FEE_USDT_ATOMIC,
    }


def _transaction_from_record(record: dict[str, object]) -> RegistrationTransaction:
    scope = record.get("scope")
    if not isinstance(scope, dict) or record.get("intent_digest") != digest(scope):
        raise InvariantViolation("ERC-8004 durable intent is malformed")
    return RegistrationTransaction(
        source=str(scope["source"]),
        agent_uri=str(scope["agent_uri"]),
        nonce=int(scope["nonce"]),
        gas_limit=int(scope["gas_limit"]),
        max_fee_per_gas=int(scope["max_fee_per_gas"]),
        max_priority_fee_per_gas=int(scope["max_priority_fee_per_gas"]),
        chain_id=int(scope["chain_id"]),
        registry=str(scope["registry"]),
        fee_currency=str(scope["fee_currency"]),
    )


def prepare_registration(
    *, vault: OperationalSecretVault, rpc: RegistrationRPC, agent_uri: str
) -> dict[str, object]:
    state = vault.load()
    identity = state["identity"]
    assert isinstance(identity, dict)
    address = normalize_address(str(identity.get("wallet_address", "")))
    existing = identity.get(REGISTRATION_RECORD)
    if isinstance(existing, dict):
        scope = existing.get("scope")
        if not isinstance(scope, dict) or scope.get("agent_uri") != agent_uri:
            raise InvariantViolation("ERC-8004 intent is already bound to another URI")
        return existing
    if rpc.chain_id() != CELO_CHAIN_ID:
        raise InvariantViolation("registration RPC is not Celo Mainnet")
    if (
        rpc.code(CELO_IDENTITY_REGISTRY) == "0x"
        or rpc.code(CELO_USDT_FEE_ADAPTER) == "0x"
        or rpc.code(CELO_FEE_CURRENCY_DIRECTORY) == "0x"
    ):
        raise InvariantViolation("registration contracts are not deployed")
    if rpc.token_decimals(CELO_MAINNET_USDT) != 6:
        raise InvariantViolation("configured Celo USDT does not have six decimals")
    if CELO_USDT_FEE_ADAPTER not in rpc.fee_currencies():
        raise InvariantViolation("Celo USDT fee adapter is not allowlisted")
    if rpc.adapted_token(address) != CELO_MAINNET_USDT:
        raise InvariantViolation("fee adapter does not resolve to Celo USDT")
    if rpc.token_balance(CELO_MAINNET_USDT, address) < MAX_FEE_USDT_ATOMIC:
        raise InvariantViolation("agent USDT balance is below the registration fee cap")
    if rpc.token_balance(CELO_USDT_FEE_ADAPTER, address) < MAX_FEE_USDT_ATOMIC * USDT_SCALE:
        raise InvariantViolation("normalized fee currency balance is below the registration cap")
    if rpc.token_balance(CELO_IDENTITY_REGISTRY, address) != 0:
        raise InvariantViolation("agent wallet already owns an ERC-8004 identity")
    draft = RegistrationTransaction(
        source=address,
        agent_uri=agent_uri,
        nonce=rpc.nonce(address),
        gas_limit=1,
        max_fee_per_gas=1,
    )
    estimated_gas = rpc.estimate(draft)
    gas_limit = (estimated_gas * (10_000 + GAS_MARGIN_BPS) + 9_999) // 10_000
    max_fee_per_gas = MAX_FEE_USDT_ATOMIC * USDT_SCALE // gas_limit
    if max_fee_per_gas < rpc.fee_gas_price():
        raise InvariantViolation("current fee exceeds the ERC-8004 registration cap")
    transaction = RegistrationTransaction(
        source=address,
        agent_uri=agent_uri,
        nonce=draft.nonce,
        gas_limit=gas_limit,
        max_fee_per_gas=max_fee_per_gas,
    )
    scope = _intent_scope(transaction)
    record: dict[str, object] = {
        "state": "INTENT_PERSISTED",
        "scope": scope,
        "intent_digest": digest(scope),
        "estimated_gas": estimated_gas,
        "observed_block": rpc.block_number(),
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    identity[REGISTRATION_RECORD] = record
    vault.save(state)
    return record


def broadcast_registration(
    *, vault: OperationalSecretVault, rpc: RegistrationRPC, agent_uri: str
) -> dict[str, object]:
    record = prepare_registration(vault=vault, rpc=rpc, agent_uri=agent_uri)
    current_state = str(record.get("state"))
    if current_state in {"BROADCAST_UNKNOWN", "BROADCAST_ACCEPTED", "RECONCILED"}:
        return reconcile_registration(vault=vault, rpc=rpc)
    if current_state not in {"INTENT_PERSISTED", "SIGNED"}:
        raise InvariantViolation("ERC-8004 registration state is not executable")
    state = vault.load()
    identity = state["identity"]
    assert isinstance(identity, dict)
    current = identity[REGISTRATION_RECORD]
    assert isinstance(current, dict)
    transaction = _transaction_from_record(current)
    if (
        rpc.chain_id() != transaction.chain_id
        or rpc.nonce(transaction.source) != transaction.nonce
        or CELO_USDT_FEE_ADAPTER not in rpc.fee_currencies()
        or rpc.adapted_token(transaction.source) != CELO_MAINNET_USDT
    ):
        raise InvariantViolation("fresh Celo registration facts diverge from durable intent")
    if rpc.fee_gas_price() > transaction.max_fee_per_gas:
        raise InvariantViolation("fresh Celo fee exceeds durable registration cap")
    if rpc.token_balance(CELO_USDT_FEE_ADAPTER, transaction.source) < (
        transaction.gas_limit * transaction.max_fee_per_gas
    ):
        raise InvariantViolation("fresh normalized USDT balance cannot cover registration cap")
    private_key = identity.get("wallet_private_key")
    if not isinstance(private_key, str):
        raise InvariantViolation("operational vault has no agent signing key")
    signed = sign_cip64(transaction, private_key)
    expected_hash = current.get("transaction_hash")
    if expected_hash is not None and expected_hash != signed.transaction_hash:
        raise InvariantViolation("re-signed ERC-8004 transaction identity diverged")
    current.update({"state": "SIGNED", "transaction_hash": signed.transaction_hash})
    vault.save(state)
    current["state"] = "BROADCAST_UNKNOWN"
    current["broadcast_started_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    vault.save(state)
    try:
        returned_hash = rpc.send(signed)
    except BroadcastUncertain:
        return {
            "state": "BROADCAST_UNKNOWN",
            "transaction_hash": signed.transaction_hash,
            "intent_digest": current["intent_digest"],
        }
    if returned_hash != signed.transaction_hash:
        return {
            "state": "BROADCAST_UNKNOWN",
            "transaction_hash": signed.transaction_hash,
            "intent_digest": current["intent_digest"],
        }
    current["state"] = "BROADCAST_ACCEPTED"
    current["broadcast_accepted_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    vault.save(state)
    return {
        "state": "BROADCAST_ACCEPTED",
        "transaction_hash": signed.transaction_hash,
        "intent_digest": current["intent_digest"],
    }


def reconcile_registration(
    *, vault: OperationalSecretVault, rpc: RegistrationRPC
) -> dict[str, object]:
    state = vault.load()
    identity = state["identity"]
    assert isinstance(identity, dict)
    record = identity.get(REGISTRATION_RECORD)
    if not isinstance(record, dict):
        raise InvariantViolation("no ERC-8004 registration intent exists")
    if record.get("state") == "RECONCILED":
        existing_evidence = record.get("evidence")
        if (
            isinstance(existing_evidence, dict)
            and existing_evidence.get("fee_observation_policy")
            == "celo-usdt-transfer-net-v1"
        ):
            return _safe_reconciliation(record)
    transaction = _transaction_from_record(record)
    tx_hash = record.get("transaction_hash")
    if not isinstance(tx_hash, str):
        raise InvariantViolation("registration intent has no transaction hash")
    chain_transaction = rpc.transaction(tx_hash)
    receipt = rpc.receipt(tx_hash)
    if chain_transaction is None or receipt is None:
        return {
            "state": str(record.get("state")),
            "transaction_hash": tx_hash,
            "outcome": "PENDING_OR_RECONCILIATION_REQUIRED",
        }
    if (
        normalize_address(str(chain_transaction.get("from"))) != transaction.source
        or normalize_address(str(chain_transaction.get("to"))) != transaction.registry
        or _quantity(chain_transaction.get("nonce"), "transaction nonce") != transaction.nonce
        or str(chain_transaction.get("input", "")).lower() != transaction.data.lower()
        or normalize_address(str(chain_transaction.get("feeCurrency")))
        != transaction.fee_currency
    ):
        raise InvariantViolation("mined transaction does not match ERC-8004 intent")
    if _quantity(receipt.get("status"), "receipt status") != 1:
        raise InvariantViolation("ERC-8004 registration transaction reverted")
    block_number = _quantity(receipt.get("blockNumber"), "receipt block number")
    block = rpc.block(block_number)
    if str(block.get("hash", "")).lower() != str(receipt.get("blockHash", "")).lower():
        raise InvariantViolation("ERC-8004 receipt is not in the canonical Celo block")
    if rpc.block_number() < block_number:
        raise InvariantViolation("ERC-8004 receipt block is ahead of Celo head")
    logs = receipt.get("logs")
    if not isinstance(logs, list):
        raise InvariantViolation("ERC-8004 receipt has malformed logs")
    owner_word = "0x" + transaction.source[2:].rjust(64, "0")
    transfers: list[tuple[int, dict[str, object]]] = []
    registrations: list[int] = []
    fee_debits: list[int] = []
    fee_refunds: list[int] = []
    for log in logs:
        if not isinstance(log, dict):
            continue
        topics = log.get("topics")
        if not isinstance(topics, list):
            continue
        normalized_topics = [str(topic).lower() for topic in topics]
        log_address = str(log.get("address", "")).lower()
        if (
            log_address == CELO_MAINNET_USDT
            and len(normalized_topics) == 3
            and normalized_topics[0] == TRANSFER_TOPIC
        ):
            amount = _quantity(log.get("data"), "USDT Transfer amount")
            if normalized_topics[1] == owner_word:
                fee_debits.append(amount)
            if normalized_topics[2] == owner_word:
                fee_refunds.append(amount)
        if log_address != transaction.registry:
            continue
        if (
            len(normalized_topics) == 4
            and normalized_topics[0] == TRANSFER_TOPIC
            and int(normalized_topics[1], 16) == 0
            and normalized_topics[2] == owner_word
        ):
            transfers.append((int(normalized_topics[3], 16), log))
        if (
            len(normalized_topics) == 3
            and normalized_topics[0] == REGISTERED_TOPIC
            and normalized_topics[2] == owner_word
        ):
            registrations.append(int(normalized_topics[1], 16))
    if len(transfers) != 1 or len(registrations) != 1 or transfers[0][0] != registrations[0]:
        raise InvariantViolation("ERC-8004 mint logs are absent or ambiguous")
    agent_id = registrations[0]
    if (
        rpc.owner_of(agent_id) != transaction.source
        or rpc.token_uri(agent_id) != transaction.agent_uri
    ):
        raise InvariantViolation("ERC-8004 registry state diverges from the intent")
    gas_used = _quantity(receipt.get("gasUsed"), "receipt gas used")
    effective_gas_price = _quantity(
        receipt.get("effectiveGasPrice"), "receipt effective gas price"
    )
    fee_atomic_18 = gas_used * effective_gas_price
    fee_calculation_floor = fee_atomic_18 // USDT_SCALE
    fee_calculation_ceiling = (fee_atomic_18 + USDT_SCALE - 1) // USDT_SCALE
    fee_usdt_atomic = sum(fee_debits) - sum(fee_refunds)
    if fee_usdt_atomic not in {fee_calculation_floor, fee_calculation_ceiling}:
        raise InvariantViolation("observed USDT fee transfers diverge from receipt gas facts")
    if fee_usdt_atomic > MAX_FEE_USDT_ATOMIC:
        raise InvariantViolation("ERC-8004 actual fee exceeds durable intent cap")
    evidence = {
        "operation": "ERC8004_REGISTER",
        "network": "eip155:42220",
        "transaction_hash": tx_hash,
        "block_number": block_number,
        "block_hash": str(receipt.get("blockHash", "")).lower(),
        "registry": transaction.registry,
        "owner": transaction.source,
        "agent_id": agent_id,
        "agent_uri": transaction.agent_uri,
        "fee_currency": transaction.fee_currency,
        "gas_used": gas_used,
        "effective_gas_price_atomic_18": effective_gas_price,
        "fee_usdt_atomic": fee_usdt_atomic,
        "fee_calculation_ceiling_usdt_atomic": fee_calculation_ceiling,
        "fee_observation_policy": "celo-usdt-transfer-net-v1",
        "fee_debit_events": len(fee_debits),
        "fee_refund_events": len(fee_refunds),
        "transfer_events": 1,
        "registered_events": 1,
    }
    record.update(
        {
            "state": "RECONCILED",
            "agent_id": agent_id,
            "evidence": evidence,
            "evidence_digest": digest(evidence),
            "reconciled_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
    )
    vault.save(state)
    return _safe_reconciliation(record)


def _safe_reconciliation(record: dict[str, object]) -> dict[str, object]:
    evidence = record.get("evidence")
    assert isinstance(evidence, dict)
    return {
        "state": "RECONCILED",
        "transaction_hash": evidence["transaction_hash"],
        "agent_id": evidence["agent_id"],
        "agent_uri": evidence["agent_uri"],
        "fee_usdt_atomic": evidence["fee_usdt_atomic"],
        "evidence_digest": record["evidence_digest"],
        "signing_key_exposed": False,
        "raw_transaction_persisted": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Register the SNE-SEC agent in ERC-8004")
    parser.add_argument("action", choices=("mint", "reconcile"))
    parser.add_argument("--agent-uri", required=False)
    parser.add_argument("--vault", default=default_vault_path(), type=str)
    parser.add_argument("--rpc-url", default=CELO_RPC_URL)
    arguments = parser.parse_args()
    vault = OperationalSecretVault(path=Path(arguments.vault))
    rpc = RegistrationRPC(arguments.rpc_url)
    try:
        if arguments.action == "mint":
            if not arguments.agent_uri:
                raise InvariantViolation("mint requires --agent-uri")
            result = broadcast_registration(
                vault=vault, rpc=rpc, agent_uri=str(arguments.agent_uri)
            )
        else:
            result = reconcile_registration(vault=vault, rpc=rpc)
    except (InvariantViolation, OSError) as exc:
        raise SystemExit(str(exc)) from None
    print(canonical_json(result))


if __name__ == "__main__":
    main()
