"""x402 v2 wiring whose delivery gate is independent Celo admission."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast
from urllib.parse import urlsplit

import httpx
from x402.http import (
    AuthHeaders,
    FacilitatorClient,
    FacilitatorConfig,
    HTTPFacilitatorClient,
    PaymentOption,
    RouteConfig,
    RoutesConfig,
)
from x402.mechanisms.evm.exact.server import ExactEvmScheme
from x402.schemas import (
    AssetAmount,
    PaymentRequirements,
    RecoveredVerifyResult,
    SettleContext,
    SettleResponse,
    SettleResultContext,
    SkipSettleResult,
    VerifyFailureContext,
    VerifyResponse,
)
from x402.server import x402ResourceServer

from .agent import AgentSettings
from .canonical import digest
from .celo_settlement import CeloRPC, CeloSettlementVerifier, HttpCeloRPC
from .errors import InvariantViolation
from .payment_store import SQLitePaymentStore
from .payments import (
    CELO_MAINNET_CAIP2,
    CELO_MAINNET_USDC,
    FacilitatorSettlementClaim,
    PaymentIntent,
    PaymentSettlement,
    authorization_identity,
    build_facilitator_claim,
    build_payment_intent,
    normalize_address,
    reconcile_settlement,
)

X402_PROTECTED_ROUTE = "GET /v1/x402/reviews/*"
CELO_FACILITATOR_URL = "https://api.x402.celo.org"
CELO_RPC_URL = "https://forno.celo.org"


@dataclass(frozen=True)
class X402Settings:
    enabled: bool
    pay_to: str | None = None
    amount_atomic: int = 10_000
    facilitator_url: str = CELO_FACILITATOR_URL
    rpc_url: str = CELO_RPC_URL
    min_confirmations: int = 1
    api_key: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if isinstance(self.amount_atomic, bool) or self.amount_atomic <= 0:
            raise InvariantViolation("x402 amount must be a positive integer")
        if not 1 <= self.min_confirmations <= 10_000:
            raise InvariantViolation("x402 confirmation policy is outside bounds")
        _https_or_loopback(self.facilitator_url, field="facilitator URL")
        _https_or_loopback(self.rpc_url, field="Celo RPC URL")
        if self.enabled:
            if self.pay_to is None:
                raise InvariantViolation("enabled x402 requires a dedicated payTo address")
            object.__setattr__(self, "pay_to", normalize_address(self.pay_to))
            if self.api_key is not None and not self.api_key.strip():
                raise InvariantViolation("x402 facilitator API key cannot be blank")
        elif self.pay_to is not None:
            object.__setattr__(self, "pay_to", normalize_address(self.pay_to))

    @classmethod
    def from_environment(cls, agent: AgentSettings) -> X402Settings:
        raw_amount = os.environ.get("SNE_SEC_CELO_X402_AMOUNT_ATOMIC", "10000")
        raw_confirmations = os.environ.get("SNE_SEC_CELO_X402_MIN_CONFIRMATIONS", "1")
        try:
            amount = int(raw_amount)
            confirmations = int(raw_confirmations)
        except ValueError as exc:
            raise InvariantViolation("x402 numeric configuration must contain integers") from exc
        return cls(
            enabled=agent.x402_enabled,
            pay_to=os.environ.get("SNE_SEC_CELO_X402_PAY_TO", agent.wallet_address),
            amount_atomic=amount,
            facilitator_url=os.environ.get(
                "SNE_SEC_CELO_X402_FACILITATOR_URL", CELO_FACILITATOR_URL
            ),
            rpc_url=os.environ.get("SNE_SEC_CELO_RPC_URL", CELO_RPC_URL),
            min_confirmations=confirmations,
            api_key=os.environ.get("SNE_SEC_CELO_X402_API_KEY"),
        )


def _https_or_loopback(value: str, *, field: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme == "https" and parsed.netloc and not parsed.username:
        return
    if (
        parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "localhost"}
        and parsed.netloc
        and not parsed.username
    ):
        return
    raise InvariantViolation(f"{field} must use HTTPS outside loopback development")


class _FacilitatorAuth:
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def get_auth_headers(self) -> AuthHeaders:
        return AuthHeaders(settle={"X-API-Key": self._api_key})


class _NoRedirectFacilitatorClient(HTTPFacilitatorClient):
    """Keep settlement credentials off redirects and ambient proxy configuration."""

    def _get_sync_client(self) -> httpx.Client:
        return httpx.Client(timeout=self._timeout, follow_redirects=False, trust_env=False)

    def _get_async_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=False,
                trust_env=False,
            )
        if not isinstance(self._http_client, httpx.AsyncClient):
            raise InvariantViolation("x402 facilitator requires an asynchronous HTTP client")
        return self._http_client


@dataclass(frozen=True)
class X402Runtime:
    routes: RoutesConfig
    server: x402ResourceServer
    store: SQLitePaymentStore


def _integer(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise InvariantViolation(f"x402 {field} must be an integer string")
    text = str(value)
    if not text.isdecimal():
        raise InvariantViolation(f"x402 {field} must be an unsigned decimal integer")
    return int(text)


PaymentHookContext = SettleContext | VerifyFailureContext


def _authorization(context: PaymentHookContext) -> dict[str, object]:
    if context.payment_payload.x402_version != 2:
        raise InvariantViolation("only x402 v2 payment payloads are admitted")
    value = context.payment_payload.payload.get("authorization")
    if not isinstance(value, dict):
        raise InvariantViolation("x402 EIP-3009 authorization is absent or malformed")
    return {str(key): item for key, item in value.items()}


def _resource(context: PaymentHookContext) -> str:
    transport = context.transport_context
    request = getattr(transport, "request", None)
    path = getattr(request, "path", None)
    method = getattr(request, "method", None)
    if method != "GET" or not isinstance(path, str):
        raise InvariantViolation("x402 settlement is not bound to the protected GET resource")
    return path


def _intent_from_context(context: PaymentHookContext, created_at: datetime) -> PaymentIntent:
    requirements = cast(PaymentRequirements, context.requirements)
    if requirements.scheme != "exact" or requirements.network != CELO_MAINNET_CAIP2:
        raise InvariantViolation("x402 requirements use an unadmitted scheme or network")
    authorization = _authorization(context)
    payer = authorization.get("from")
    payee = authorization.get("to")
    nonce = authorization.get("nonce")
    if not all(isinstance(value, str) for value in (payer, payee, nonce)):
        raise InvariantViolation("x402 authorization identities are malformed")
    amount = _integer(authorization.get("value"), field="authorization value")
    valid_after = _integer(authorization.get("validAfter"), field="validAfter")
    valid_before = _integer(authorization.get("validBefore"), field="validBefore")
    requirement_amount = _integer(requirements.amount, field="required amount")
    if amount != requirement_amount:
        raise InvariantViolation("x402 authorization amount differs from requirements")
    if normalize_address(str(payee)) != normalize_address(requirements.pay_to):
        raise InvariantViolation("x402 authorization payee differs from requirements")
    return build_payment_intent(
        resource=_resource(context),
        network=str(requirements.network),
        asset=requirements.asset,
        amount_atomic=amount,
        payer=str(payer),
        payee=str(payee),
        nonce=str(nonce),
        valid_after=valid_after,
        valid_before=valid_before,
        created_at=created_at,
    )


def _authorization_id_from_context(context: PaymentHookContext) -> str:
    requirements = cast(PaymentRequirements, context.requirements)
    authorization = _authorization(context)
    payer = authorization.get("from")
    nonce = authorization.get("nonce")
    if not isinstance(payer, str) or not isinstance(nonce, str):
        raise InvariantViolation("x402 authorization identity is malformed")
    return authorization_identity(
        network=str(requirements.network),
        asset=requirements.asset,
        payer=payer,
        nonce=nonce,
    )


def build_x402_runtime(
    *,
    settings: X402Settings,
    store: SQLitePaymentStore,
    facilitator: FacilitatorClient | None = None,
    rpc: CeloRPC | None = None,
    clock: Callable[[], datetime] | None = None,
) -> X402Runtime:
    if not settings.enabled or settings.pay_to is None:
        raise InvariantViolation("cannot construct x402 runtime while payments are disabled")
    now = clock or (lambda: datetime.now(UTC))
    if facilitator is None:
        if settings.api_key is None:
            raise InvariantViolation("enabled x402 requires a facilitator API key")
        client: FacilitatorClient = _NoRedirectFacilitatorClient(
            FacilitatorConfig(
                url=settings.facilitator_url,
                auth_provider=_FacilitatorAuth(settings.api_key),
                identifier="celo-hosted-facilitator",
            )
        )
    else:
        client = facilitator
    server = x402ResourceServer(client)
    # x402 2.22.0 ships a runtime-compatible scheme whose published annotations
    # narrow ``payment_flows`` differently from its own SchemeNetworkServer protocol.
    server.register(
        CELO_MAINNET_CAIP2,
        ExactEvmScheme(),  # type: ignore[no-untyped-call,arg-type]
    )
    observer = CeloSettlementVerifier(
        rpc or HttpCeloRPC(settings.rpc_url),
        source_configuration_digest=digest(
            {
                "source_id": "celo_mainnet_confirmation_rpc",
                "network": CELO_MAINNET_CAIP2,
                "endpoint_identity": settings.rpc_url.rstrip("/"),
                "min_confirmations": settings.min_confirmations,
                "finality": "latest_canonical_confirmations",
            }
        ),
        min_confirmations=settings.min_confirmations,
    )

    async def admit_claim(
        intent: PaymentIntent, claim: FacilitatorSettlementClaim
    ) -> PaymentSettlement:
        observation = await observer.verify(intent=intent, claim=claim, observed_at=now())
        settlement = reconcile_settlement(
            intent=intent,
            claim=claim,
            observation=observation,
            settled_at=now(),
        )
        store.admit_settlement(observation, settlement)
        return settlement

    async def before_settle(context: SettleContext) -> SkipSettleResult | None:
        intent = _intent_from_context(context, now())
        if intent.payee != settings.pay_to or intent.amount_atomic != settings.amount_atomic:
            raise InvariantViolation("x402 payment differs from the configured offer")
        store.record_intent(intent)
        prior_claim = store.claim_for_authorization(intent.authorization_id)
        if prior_claim is None:
            return None
        await admit_claim(intent, prior_claim)
        return SkipSettleResult(
            SettleResponse(
                success=True,
                transaction=prior_claim.transaction_hash,
                network=prior_claim.network,
                payer=prior_claim.payer,
                amount=str(prior_claim.amount_atomic),
            )
        )

    async def after_settle(context: SettleResultContext) -> None:
        intent = store.get_intent_by_authorization(_authorization_id_from_context(context))
        result = context.result
        if result.payer is None or result.amount is None:
            raise InvariantViolation("facilitator settlement claim omits payer or amount")
        claimed_at = now()
        claim = build_facilitator_claim(
            intent=intent,
            transaction_hash=result.transaction,
            network=str(result.network),
            payer=result.payer,
            amount_atomic=_integer(result.amount, field="settled amount"),
            claimed_at=claimed_at,
        )
        store.record_claim(claim)
        await admit_claim(intent, claim)

    async def recover_claim(context: VerifyFailureContext) -> RecoveredVerifyResult | None:
        try:
            authorization_id = _authorization_id_from_context(context)
            intent = store.get_intent_by_authorization(authorization_id)
            claim = store.claim_for_authorization(authorization_id)
            if claim is None:
                return None
            await admit_claim(intent, claim)
        except Exception:
            return None
        return RecoveredVerifyResult(VerifyResponse(is_valid=True, payer=intent.payer))

    server.on_before_settle(before_settle)
    server.on_after_settle(after_settle)
    server.on_verify_failure(recover_claim)
    routes: RoutesConfig = {
        X402_PROTECTED_ROUTE: RouteConfig(
            accepts=PaymentOption(
                scheme="exact",
                network=CELO_MAINNET_CAIP2,
                pay_to=settings.pay_to,
                price=AssetAmount(
                    amount=str(settings.amount_atomic),
                    asset=CELO_MAINNET_USDC,
                    extra={"name": "USDC", "version": "2"},
                ),
                max_timeout_seconds=300,
            ),
            description="Deliver one immutable SNE-SEC evidence-backed Review",
            mime_type="application/json",
            service_name="SNE-SEC Review Delivery",
            tags=["security", "evidence", "celo", "x402"],
        )
    }
    return X402Runtime(routes=routes, server=server, store=store)
