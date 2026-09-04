"""Independent, fail-closed admission of direct Celo EIP-3009 settlements."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Protocol

import httpx

from .canonical import digest
from .errors import InvariantViolation
from .payments import (
    CELO_MAINNET_CHAIN_ID,
    CeloSettlementObservation,
    FacilitatorSettlementClaim,
    PaymentIntent,
    authorization_identity,
    normalize_address,
    normalize_hash,
)

ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TRANSFER_WITH_AUTHORIZATION_SELECTOR = "e3ee160e"
_HEX_DATA = re.compile(r"^0x(?:[0-9a-fA-F]{2})+$")
_HEX_QUANTITY = re.compile(r"^0x[0-9a-fA-F]+$")


class CeloRPC(Protocol):
    async def call(self, method: str, params: list[Any]) -> Any: ...


class HttpCeloRPC:
    def __init__(self, url: str, *, timeout_seconds: float = 15.0) -> None:
        self.url = url
        self.timeout_seconds = timeout_seconds
        self._request_id = 0

    async def call(self, method: str, params: list[Any]) -> Any:
        self._request_id += 1
        payload = {"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": params}
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = await client.post(self.url, json=payload)
        response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict) or value.get("error") is not None or "result" not in value:
            raise InvariantViolation("Celo RPC returned an invalid response")
        return value["result"]


def _mapping(value: object, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise InvariantViolation(f"Celo {field} is absent or malformed")
    return value


def _quantity(value: object, *, field: str) -> int:
    if not isinstance(value, str) or not _HEX_QUANTITY.fullmatch(value):
        raise InvariantViolation(f"Celo {field} is not a hex quantity")
    return int(value, 16)


def _data_word(value: object, *, field: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
        raise InvariantViolation(f"Celo {field} is not a 32-byte data word")
    return int(value, 16)


def _word_address(word: bytes, *, field: str) -> str:
    if len(word) != 32 or any(word[:12]):
        raise InvariantViolation(f"EIP-3009 {field} address is not canonically encoded")
    return normalize_address("0x" + word[12:].hex())


def _decode_authorization(data: object) -> tuple[str, str, int, int, int, str]:
    if not isinstance(data, str) or not _HEX_DATA.fullmatch(data):
        raise InvariantViolation("Celo transaction input is absent or malformed")
    raw = bytes.fromhex(data[2:])
    minimum = 4 + (9 * 32)
    if len(raw) < minimum or raw[:4].hex() != TRANSFER_WITH_AUTHORIZATION_SELECTOR:
        raise InvariantViolation("Celo transaction is not a direct EIP-3009 transfer")
    words = [raw[4 + offset : 4 + offset + 32] for offset in range(0, 9 * 32, 32)]
    payer = _word_address(words[0], field="payer")
    payee = _word_address(words[1], field="payee")
    amount = int.from_bytes(words[2], "big")
    valid_after = int.from_bytes(words[3], "big")
    valid_before = int.from_bytes(words[4], "big")
    nonce = "0x" + words[5].hex()
    if int.from_bytes(words[6], "big") not in {0, 1, 27, 28}:
        raise InvariantViolation("EIP-3009 signature recovery identifier is malformed")
    return payer, payee, amount, valid_after, valid_before, nonce


class CeloSettlementVerifier:
    def __init__(
        self,
        rpc: CeloRPC,
        *,
        source_configuration_digest: str,
        source_id: str = "celo_mainnet_confirmation_rpc",
        min_confirmations: int = 1,
    ) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]{2,127}", source_id):
            raise InvariantViolation("Celo observation source ID is malformed")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", source_configuration_digest):
            raise InvariantViolation("Celo source configuration digest is malformed")
        if not 1 <= min_confirmations <= 10_000:
            raise InvariantViolation("Celo confirmation policy is outside bounds")
        self.rpc = rpc
        self.source_id = source_id
        self.source_configuration_digest = source_configuration_digest
        self.min_confirmations = min_confirmations

    async def verify(
        self,
        *,
        intent: PaymentIntent,
        claim: FacilitatorSettlementClaim,
        observed_at: datetime,
    ) -> CeloSettlementObservation:
        if claim.intent_id != intent.intent_id:
            raise InvariantViolation("facilitator claim belongs to another payment intent")
        if claim.transaction_hash == "0x" + ("0" * 64):
            raise InvariantViolation("facilitator claim has a zero transaction hash")

        tx_hash = claim.transaction_hash
        chain_id_raw = await self.rpc.call("eth_chainId", [])
        if _quantity(chain_id_raw, field="chain ID") != CELO_MAINNET_CHAIN_ID:
            raise InvariantViolation("RPC belongs to another chain")

        receipt_raw = await self.rpc.call("eth_getTransactionReceipt", [tx_hash])
        transaction_raw = await self.rpc.call("eth_getTransactionByHash", [tx_hash])
        policy_head_raw = await self.rpc.call("eth_getBlockByNumber", ["latest", False])
        receipt = _mapping(receipt_raw, field="transaction receipt")
        transaction = _mapping(transaction_raw, field="transaction")
        policy_head = _mapping(policy_head_raw, field="confirmation policy head")

        if normalize_hash(str(receipt.get("transactionHash", "")), field="receipt hash") != tx_hash:
            raise InvariantViolation("Celo receipt does not match the facilitator claim")
        if normalize_hash(str(transaction.get("hash", "")), field="transaction hash") != tx_hash:
            raise InvariantViolation("Celo transaction does not match the facilitator claim")
        if _quantity(receipt.get("status"), field="receipt status") != 1:
            raise InvariantViolation("Celo settlement transaction did not succeed")

        token = normalize_address(str(transaction.get("to", "")))
        if token != intent.asset:
            raise InvariantViolation("Celo settlement transaction targets another asset")
        payer, payee, amount, valid_after, valid_before, nonce = _decode_authorization(
            transaction.get("input")
        )
        if (
            payer != intent.payer
            or payee != intent.payee
            or amount != intent.amount_atomic
            or valid_after != intent.valid_after
            or valid_before != intent.valid_before
        ):
            raise InvariantViolation("on-chain EIP-3009 authorization differs from the intent")
        authorization_id = authorization_identity(
            network=intent.network,
            asset=token,
            payer=payer,
            nonce=nonce,
        )
        if authorization_id != intent.authorization_id:
            raise InvariantViolation("on-chain EIP-3009 nonce differs from the intent")

        block_number = _quantity(receipt.get("blockNumber"), field="receipt block number")
        block_hash = normalize_hash(str(receipt.get("blockHash", "")), field="receipt block hash")
        transaction_block_hash = normalize_hash(
            str(transaction.get("blockHash", "")), field="transaction block hash"
        )
        transaction_block_number = _quantity(
            transaction.get("blockNumber"), field="transaction block number"
        )
        if transaction_block_hash != block_hash or transaction_block_number != block_number:
            raise InvariantViolation("Celo transaction and receipt block bindings differ")

        canonical_raw = await self.rpc.call("eth_getBlockByNumber", [hex(block_number), False])
        canonical = _mapping(canonical_raw, field="canonical block")
        canonical_hash = normalize_hash(
            str(canonical.get("hash", "")), field="canonical block hash"
        )
        canonical_number = _quantity(canonical.get("number"), field="canonical block number")
        if canonical_hash != block_hash or canonical_number != block_number:
            raise InvariantViolation("Celo settlement receipt is no longer canonical")
        policy_head_number = _quantity(
            policy_head.get("number"), field="confirmation policy head number"
        )
        normalize_hash(
            str(policy_head.get("hash", "")), field="confirmation policy head hash"
        )
        if policy_head_number < block_number:
            raise InvariantViolation("Celo settlement block is above the confirmation policy head")
        confirmations = policy_head_number - block_number + 1
        if confirmations < self.min_confirmations:
            raise InvariantViolation("Celo settlement has insufficient confirmations")

        logs = receipt.get("logs")
        if not isinstance(logs, list):
            raise InvariantViolation("Celo settlement logs are malformed")
        matches: list[int] = []
        for raw_log in logs:
            if not isinstance(raw_log, dict):
                continue
            topics = raw_log.get("topics")
            if (
                str(raw_log.get("address", "")).lower() != token
                or not isinstance(topics, list)
                or len(topics) != 3
                or str(topics[0]).lower() != ERC20_TRANSFER_TOPIC
            ):
                continue
            from_topic = str(topics[1]).lower()
            to_topic = str(topics[2]).lower()
            if not (
                re.fullmatch(r"0x[0-9a-f]{64}", from_topic)
                and re.fullmatch(r"0x[0-9a-f]{64}", to_topic)
                and from_topic[:26] == "0x" + ("0" * 24)
                and to_topic[:26] == "0x" + ("0" * 24)
                and from_topic[-40:] == payer[2:]
                and to_topic[-40:] == payee[2:]
            ):
                continue
            if _data_word(raw_log.get("data"), field="transfer amount") != amount:
                continue
            if raw_log.get("removed") is True:
                continue
            if "transactionHash" in raw_log and str(raw_log["transactionHash"]).lower() != tx_hash:
                continue
            if "blockHash" in raw_log and str(raw_log["blockHash"]).lower() != block_hash:
                continue
            matches.append(_quantity(raw_log.get("logIndex"), field="transfer log index"))
        if len(matches) != 1:
            raise InvariantViolation("Celo transfer evidence is absent or ambiguous")
        log_index = matches[0]
        external_event_id = f"{intent.network}:{tx_hash}:{log_index}"
        identity = digest(
            {
                "source_id": self.source_id,
                "external_event_id": external_event_id,
                "authorization_id": authorization_id,
            }
        )
        return CeloSettlementObservation(
            observation_id="payment_observation_" + identity.removeprefix("sha256:")[:32],
            source_id=self.source_id,
            source_configuration_digest=self.source_configuration_digest,
            external_event_id=external_event_id,
            intent_id=intent.intent_id,
            authorization_id=authorization_id,
            network=intent.network,
            chain_id=intent.chain_id,
            asset=token,
            symbol=intent.symbol,
            decimals=intent.decimals,
            transaction_hash=tx_hash,
            log_index=log_index,
            payer=payer,
            payee=payee,
            amount_atomic=amount,
            block_number=block_number,
            block_hash=block_hash,
            policy_head_block_number=policy_head_number,
            confirmations=confirmations,
            observed_at=observed_at,
            raw_response_digest=digest(
                {
                    "chain_id": chain_id_raw,
                    "receipt": receipt_raw,
                    "transaction": transaction_raw,
                    "confirmation_policy_head": policy_head_raw,
                    "canonical_block": canonical_raw,
                }
            ),
        )
