"""Closed x402 payment and independently observed Celo settlement records."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from .canonical import digest
from .errors import InvariantViolation

CELO_MAINNET_CHAIN_ID = 42220
CELO_MAINNET_CAIP2 = "eip155:42220"
CELO_MAINNET_USDC = "0xcEBA9300f2b948710d2653dD7B07f33A8B32118C"
CELO_MAINNET_USDC_DECIMALS = 6
PAYMENT_INTENT_POLICY_VERSION = "sne-sec-celo-x402-intent-v1"
SETTLEMENT_POLICY_VERSION = "sne-sec-celo-settlement-v1"
CELO_FINALITY_POLICY_VERSION = "celo-canonical-confirmations-v1"

_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z][a-z0-9_]{2,127}$")
_MAX_UINT256 = 2**256 - 1


def normalize_address(value: str) -> str:
    if not _ADDRESS.fullmatch(value):
        raise InvariantViolation("EVM address must contain exactly 20 bytes")
    return value.lower()


def normalize_hash(value: str, *, field: str) -> str:
    if not _HASH.fullmatch(value):
        raise InvariantViolation(f"{field} must contain exactly 32 bytes")
    return value.lower()


def _aware(value: datetime, *, field: str) -> None:
    if value.tzinfo is None:
        raise InvariantViolation(f"{field} must be timezone-aware")


def _positive_uint256(value: int, *, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= _MAX_UINT256:
        raise InvariantViolation(f"{field} must be a positive uint256 integer")


def authorization_identity(*, network: str, asset: str, payer: str, nonce: str) -> str:
    nonce_value = normalize_hash(nonce, field="authorization nonce")
    return digest(
        {
            "network": network,
            "asset": normalize_address(asset),
            "payer": normalize_address(payer),
            "nonce": nonce_value,
        }
    )


@dataclass(frozen=True)
class PaymentIntent:
    intent_id: str
    resource: str
    network: str
    chain_id: int
    asset: str
    symbol: str
    decimals: int
    amount_atomic: int
    payer: str
    payee: str
    authorization_id: str
    valid_after: int
    valid_before: int
    created_at: datetime
    policy_version: str = PAYMENT_INTENT_POLICY_VERSION

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.intent_id):
            raise InvariantViolation("payment intent ID is malformed")
        if not self.resource.startswith("/v1/x402/") or "?" in self.resource:
            raise InvariantViolation("payment resource must be a query-free x402 API path")
        if self.network != CELO_MAINNET_CAIP2 or self.chain_id != CELO_MAINNET_CHAIN_ID:
            raise InvariantViolation("payment intent must target Celo mainnet")
        if self.symbol != "USDC" or self.decimals != CELO_MAINNET_USDC_DECIMALS:
            raise InvariantViolation("payment intent asset metadata is not admitted")
        asset = normalize_address(self.asset)
        if asset != CELO_MAINNET_USDC.lower():
            raise InvariantViolation("payment intent asset is not Celo mainnet USDC")
        _positive_uint256(self.amount_atomic, field="payment amount")
        if not 0 <= self.valid_after < self.valid_before <= _MAX_UINT256:
            raise InvariantViolation("payment authorization validity window is invalid")
        if not _DIGEST.fullmatch(self.authorization_id):
            raise InvariantViolation("payment authorization identity is malformed")
        _aware(self.created_at, field="payment intent time")
        created_epoch = int(self.created_at.timestamp())
        if not self.valid_after < created_epoch < self.valid_before:
            raise InvariantViolation("payment authorization is not valid at intent admission")
        if self.policy_version != PAYMENT_INTENT_POLICY_VERSION:
            raise InvariantViolation("payment intent policy version is not admitted")
        payer = normalize_address(self.payer)
        payee = normalize_address(self.payee)
        expected_identity = digest(
            {
                "resource": self.resource,
                "network": self.network,
                "asset": asset,
                "amount_atomic": self.amount_atomic,
                "payer": payer,
                "payee": payee,
                "authorization_id": self.authorization_id,
                "valid_after": self.valid_after,
                "valid_before": self.valid_before,
                "policy_version": self.policy_version,
            }
        )
        if self.intent_id != "payment_intent_" + expected_identity.removeprefix("sha256:")[:32]:
            raise InvariantViolation("payment intent ID does not match its content")
        object.__setattr__(self, "asset", asset)
        object.__setattr__(self, "payer", payer)
        object.__setattr__(self, "payee", payee)


def build_payment_intent(
    *,
    resource: str,
    network: str,
    asset: str,
    amount_atomic: int,
    payer: str,
    payee: str,
    nonce: str,
    valid_after: int,
    valid_before: int,
    created_at: datetime,
) -> PaymentIntent:
    authorization_id = authorization_identity(
        network=network,
        asset=asset,
        payer=payer,
        nonce=nonce,
    )
    identity = digest(
        {
            "resource": resource,
            "network": network,
            "asset": normalize_address(asset),
            "amount_atomic": amount_atomic,
            "payer": normalize_address(payer),
            "payee": normalize_address(payee),
            "authorization_id": authorization_id,
            "valid_after": valid_after,
            "valid_before": valid_before,
            "policy_version": PAYMENT_INTENT_POLICY_VERSION,
        }
    )
    return PaymentIntent(
        intent_id="payment_intent_" + identity.removeprefix("sha256:")[:32],
        resource=resource,
        network=network,
        chain_id=CELO_MAINNET_CHAIN_ID,
        asset=asset,
        symbol="USDC",
        decimals=CELO_MAINNET_USDC_DECIMALS,
        amount_atomic=amount_atomic,
        payer=payer,
        payee=payee,
        authorization_id=authorization_id,
        valid_after=valid_after,
        valid_before=valid_before,
        created_at=created_at,
    )


@dataclass(frozen=True)
class FacilitatorSettlementClaim:
    claim_id: str
    intent_id: str
    transaction_hash: str
    network: str
    payer: str
    amount_atomic: int
    claimed_at: datetime
    response_digest: str

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.claim_id) or not _ID.fullmatch(self.intent_id):
            raise InvariantViolation("facilitator claim identity is malformed")
        if self.network != CELO_MAINNET_CAIP2:
            raise InvariantViolation("facilitator claim belongs to another network")
        transaction_hash = normalize_hash(self.transaction_hash, field="transaction hash")
        payer = normalize_address(self.payer)
        _positive_uint256(self.amount_atomic, field="facilitator-claimed amount")
        _aware(self.claimed_at, field="facilitator claim time")
        if not _DIGEST.fullmatch(self.response_digest):
            raise InvariantViolation("facilitator response digest is malformed")
        expected_response_digest = digest(
            {
                "success": True,
                "transaction": transaction_hash,
                "network": self.network,
                "payer": payer,
                "amount": str(self.amount_atomic),
            }
        )
        if self.response_digest != expected_response_digest:
            raise InvariantViolation("facilitator response digest does not match its claim")
        expected_claim_identity = digest(
            {
                "intent_id": self.intent_id,
                "transaction_hash": transaction_hash,
                "response_digest": self.response_digest,
            }
        )
        if self.claim_id != "facilitator_claim_" + expected_claim_identity.removeprefix(
            "sha256:"
        )[:32]:
            raise InvariantViolation("facilitator claim ID does not match its content")
        object.__setattr__(self, "transaction_hash", transaction_hash)
        object.__setattr__(self, "payer", payer)


def build_facilitator_claim(
    *,
    intent: PaymentIntent,
    transaction_hash: str,
    network: str,
    payer: str,
    amount_atomic: int,
    claimed_at: datetime,
) -> FacilitatorSettlementClaim:
    normalized_transaction = normalize_hash(transaction_hash, field="transaction hash")
    normalized_payer = normalize_address(payer)
    response_digest = digest(
        {
            "success": True,
            "transaction": normalized_transaction,
            "network": network,
            "payer": normalized_payer,
            "amount": str(amount_atomic),
        }
    )
    identity = digest(
        {
            "intent_id": intent.intent_id,
            "transaction_hash": normalized_transaction,
            "response_digest": response_digest,
        }
    )
    return FacilitatorSettlementClaim(
        claim_id="facilitator_claim_" + identity.removeprefix("sha256:")[:32],
        intent_id=intent.intent_id,
        transaction_hash=normalized_transaction,
        network=network,
        payer=normalized_payer,
        amount_atomic=amount_atomic,
        claimed_at=claimed_at,
        response_digest=response_digest,
    )


@dataclass(frozen=True)
class CeloSettlementObservation:
    observation_id: str
    source_id: str
    source_configuration_digest: str
    external_event_id: str
    intent_id: str
    authorization_id: str
    network: str
    chain_id: int
    asset: str
    symbol: str
    decimals: int
    transaction_hash: str
    log_index: int
    payer: str
    payee: str
    amount_atomic: int
    block_number: int
    block_hash: str
    policy_head_block_number: int
    confirmations: int
    observed_at: datetime
    raw_response_digest: str
    finality_policy_version: str = CELO_FINALITY_POLICY_VERSION

    def __post_init__(self) -> None:
        identities = (self.observation_id, self.source_id, self.intent_id)
        if any(not _ID.fullmatch(value) for value in identities):
            raise InvariantViolation("settlement observation identity is malformed")
        if not self.external_event_id.strip():
            raise InvariantViolation("settlement external event identity is required")
        if not _DIGEST.fullmatch(self.source_configuration_digest):
            raise InvariantViolation("settlement source configuration digest is malformed")
        if self.network != CELO_MAINNET_CAIP2 or self.chain_id != CELO_MAINNET_CHAIN_ID:
            raise InvariantViolation("settlement observation belongs to another network")
        if self.symbol != "USDC" or self.decimals != CELO_MAINNET_USDC_DECIMALS:
            raise InvariantViolation("settlement observation asset metadata is not admitted")
        asset = normalize_address(self.asset)
        if asset != CELO_MAINNET_USDC.lower():
            raise InvariantViolation("settlement observation asset is not Celo mainnet USDC")
        if not _DIGEST.fullmatch(self.authorization_id):
            raise InvariantViolation("settlement authorization identity is malformed")
        if self.log_index < 0 or self.block_number < 0 or self.policy_head_block_number < 0:
            raise InvariantViolation("settlement chain positions cannot be negative")
        if (
            self.policy_head_block_number < self.block_number
            or self.confirmations != self.policy_head_block_number - self.block_number + 1
        ):
            raise InvariantViolation("settlement observation lacks required confirmations")
        _positive_uint256(self.amount_atomic, field="observed amount")
        object.__setattr__(self, "asset", asset)
        transaction_hash = normalize_hash(self.transaction_hash, field="transaction hash")
        block_hash = normalize_hash(self.block_hash, field="block hash")
        payer = normalize_address(self.payer)
        payee = normalize_address(self.payee)
        expected_external_event_id = f"{self.network}:{transaction_hash}:{self.log_index}"
        if self.external_event_id != expected_external_event_id:
            raise InvariantViolation("settlement external event ID does not match its content")
        expected_observation_identity = digest(
            {
                "source_id": self.source_id,
                "external_event_id": self.external_event_id,
                "authorization_id": self.authorization_id,
            }
        )
        expected_observation_id = (
            "payment_observation_"
            + expected_observation_identity.removeprefix("sha256:")[:32]
        )
        if self.observation_id != expected_observation_id:
            raise InvariantViolation("settlement observation ID does not match its content")
        object.__setattr__(self, "transaction_hash", transaction_hash)
        object.__setattr__(self, "block_hash", block_hash)
        object.__setattr__(self, "payer", payer)
        object.__setattr__(self, "payee", payee)
        _aware(self.observed_at, field="settlement observation time")
        if not _DIGEST.fullmatch(self.raw_response_digest):
            raise InvariantViolation("settlement response digest is malformed")
        if self.finality_policy_version != CELO_FINALITY_POLICY_VERSION:
            raise InvariantViolation("settlement finality policy version is not admitted")


@dataclass(frozen=True)
class PaymentSettlement:
    settlement_id: str
    intent_id: str
    claim_id: str
    observation_id: str
    external_event_id: str
    authorization_id: str
    settled_at: datetime
    reconciliation_policy_version: str = SETTLEMENT_POLICY_VERSION

    def __post_init__(self) -> None:
        identities = (self.settlement_id, self.intent_id, self.claim_id, self.observation_id)
        if any(not _ID.fullmatch(value) for value in identities):
            raise InvariantViolation("payment settlement identity is malformed")
        if not self.external_event_id.strip() or not _DIGEST.fullmatch(self.authorization_id):
            raise InvariantViolation("payment settlement binding is malformed")
        _aware(self.settled_at, field="settlement time")
        if self.reconciliation_policy_version != SETTLEMENT_POLICY_VERSION:
            raise InvariantViolation("settlement policy version is not admitted")
        expected_identity = digest(
            {
                "intent_id": self.intent_id,
                "claim_id": self.claim_id,
                "observation_id": self.observation_id,
                "external_event_id": self.external_event_id,
                "authorization_id": self.authorization_id,
                "policy_version": self.reconciliation_policy_version,
            }
        )
        if self.settlement_id != "settlement_" + expected_identity.removeprefix("sha256:")[:32]:
            raise InvariantViolation("payment settlement ID does not match its content")


def reconcile_settlement(
    *,
    intent: PaymentIntent,
    claim: FacilitatorSettlementClaim,
    observation: CeloSettlementObservation,
    settled_at: datetime,
) -> PaymentSettlement:
    if claim.intent_id != intent.intent_id or observation.intent_id != intent.intent_id:
        raise InvariantViolation("payment records belong to different intents")
    if claim.transaction_hash != observation.transaction_hash:
        raise InvariantViolation("facilitator claim and chain observation transactions differ")
    if claim.network != intent.network or observation.network != intent.network:
        raise InvariantViolation("payment network does not match the intent")
    if claim.payer != intent.payer or observation.payer != intent.payer:
        raise InvariantViolation("payment payer does not match the intent")
    if (
        claim.amount_atomic != intent.amount_atomic
        or observation.amount_atomic != intent.amount_atomic
    ):
        raise InvariantViolation("payment amount does not match the intent")
    if observation.asset != intent.asset or observation.payee != intent.payee:
        raise InvariantViolation("payment asset or payee does not match the intent")
    if observation.authorization_id != intent.authorization_id:
        raise InvariantViolation("payment authorization does not match the intent")
    _aware(settled_at, field="settlement time")
    identity = digest(
        {
            "intent_id": intent.intent_id,
            "claim_id": claim.claim_id,
            "observation_id": observation.observation_id,
            "external_event_id": observation.external_event_id,
            "authorization_id": intent.authorization_id,
            "policy_version": SETTLEMENT_POLICY_VERSION,
        }
    )
    return PaymentSettlement(
        settlement_id="settlement_" + identity.removeprefix("sha256:")[:32],
        intent_id=intent.intent_id,
        claim_id=claim.claim_id,
        observation_id=observation.observation_id,
        external_event_id=observation.external_event_id,
        authorization_id=intent.authorization_id,
        settled_at=settled_at,
    )
