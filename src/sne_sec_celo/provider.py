"""Executable, low-impact reference assessment provider."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol
from uuid import uuid4

from .canonical import digest
from .domain import CompletedReview, Observation
from .errors import CollectionFailed
from .evidence import CollectorRegistration, EvidenceAdmissionPolicy
from .rules import RuleEngine, RuleSet, load_reference_ruleset
from .targets import (
    AdmittedResolution,
    CollectionURL,
    SystemResolver,
    admit_resolution,
    normalize_origin,
    normalize_redirect,
)
from .transport import HttpExchange, PinnedHttpTransport

REFERENCE_PROVIDER_ID = "sne-sec-celo-reference"
REFERENCE_SCANNER_VERSION = "1.0.0"
REFERENCE_COLLECTOR_ID = "reference-http"
REFERENCE_COLLECTOR_VERSION = "1.0.0"
MAX_REDIRECTS = 5
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_OBSERVED_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


class Resolver(Protocol):
    async def resolve(self, target: CollectionURL) -> tuple[str, ...]: ...


class Transport(Protocol):
    async def fetch(self, resolution: AdmittedResolution) -> HttpExchange: ...


class AssessmentProvider(Protocol):
    provider_id: str

    async def assess(self, target: str) -> CompletedReview: ...


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


class ReferenceAssessmentProvider:
    provider_id = REFERENCE_PROVIDER_ID

    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        transport: Transport | None = None,
        ruleset: RuleSet | None = None,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[str], str] | None = None,
    ) -> None:
        self._resolver = resolver or SystemResolver()
        self._transport = transport or PinnedHttpTransport()
        self._ruleset = ruleset or load_reference_ruleset()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._id_factory = id_factory or _new_id
        self._admission = EvidenceAdmissionPolicy(
            (
                CollectorRegistration(
                    REFERENCE_COLLECTOR_ID,
                    REFERENCE_COLLECTOR_VERSION,
                    frozenset({"HTTP_RESPONSE", "HTTP_REDIRECT", "HTTP_HEADER"}),
                ),
            )
        )

    async def assess(self, target: str) -> CompletedReview:
        requested_at = self._clock()
        review_id = self._id_factory("review")
        initial = normalize_origin(target)
        observations, final_target = await self._collect(review_id, initial)
        admitted_at = self._clock()
        evidence = tuple(
            self._admission.admit(
                observation,
                review_id=review_id,
                target_origin=initial.origin,
                evidence_id=self._id_factory("evidence"),
                admitted_at=admitted_at,
            )
            for observation in observations
        )
        evaluated_at = self._clock()
        evaluations, findings = RuleEngine(self._ruleset).evaluate_all(
            review_id=review_id,
            scheme=final_target.scheme,
            observations=observations,
            evidence=evidence,
            evaluated_at=evaluated_at,
            id_factory=self._id_factory,
        )
        return CompletedReview(
            review_id=review_id,
            target_origin=initial.origin,
            provider_id=self.provider_id,
            scanner_version=REFERENCE_SCANNER_VERSION,
            ruleset_version=self._ruleset.version,
            requested_at=requested_at,
            completed_at=self._clock(),
            observations=observations,
            evidence=evidence,
            evaluations=evaluations,
            findings=findings,
        )

    async def _collect(
        self, review_id: str, initial: CollectionURL
    ) -> tuple[tuple[Observation, ...], CollectionURL]:
        current = initial
        visited: set[str] = set()
        observations: list[Observation] = []
        for redirect_count in range(MAX_REDIRECTS + 1):
            if current.url in visited:
                raise CollectionFailed("redirect loop detected")
            visited.add(current.url)
            answers = await self._resolver.resolve(current)
            resolution = admit_resolution(current, answers)
            exchange = await self._transport.fetch(resolution)
            observed_at = self._clock()
            observations.append(
                self._observation(
                    review_id=review_id,
                    target_origin=initial.origin,
                    kind="HTTP_RESPONSE",
                    key=f"response-{redirect_count}",
                    value={
                        "status_code": exchange.status_code,
                        "scheme": current.scheme,
                        "selected_address": exchange.selected_address,
                        "connected_peer": exchange.connected_peer,
                    },
                    source=current.public_source,
                    observed_at=observed_at,
                    receipt_digest=exchange.receipt_digest,
                )
            )
            if exchange.status_code not in _REDIRECT_STATUSES:
                observations.extend(
                    self._header_observations(
                        review_id, initial.origin, current, exchange, observed_at
                    )
                )
                return tuple(observations), current

            locations = exchange.values("location")
            if len(locations) != 1:
                raise CollectionFailed("redirect response requires exactly one Location header")
            if redirect_count == MAX_REDIRECTS:
                raise CollectionFailed("redirect limit exceeded")
            destination = normalize_redirect(locations[0], base_url=current.url)
            observations.append(
                self._observation(
                    review_id=review_id,
                    target_origin=initial.origin,
                    kind="HTTP_REDIRECT",
                    key=f"redirect-{redirect_count}",
                    value={
                        "status_code": exchange.status_code,
                        "destination_origin": destination.origin,
                        "downgrade": current.scheme == "https" and destination.scheme == "http",
                    },
                    source=current.public_source,
                    observed_at=observed_at,
                    receipt_digest=exchange.receipt_digest,
                )
            )
            current = destination
        raise CollectionFailed("redirect state escaped its closed bound")

    def _header_observations(
        self,
        review_id: str,
        target_origin: str,
        target: CollectionURL,
        exchange: HttpExchange,
        observed_at: datetime,
    ) -> tuple[Observation, ...]:
        return tuple(
            self._observation(
                review_id=review_id,
                target_origin=target_origin,
                kind="HTTP_HEADER",
                key=name,
                value={"present": bool(exchange.values(name))},
                source=target.public_source,
                observed_at=observed_at,
                receipt_digest=exchange.receipt_digest,
            )
            for name in _OBSERVED_SECURITY_HEADERS
        )

    def _observation(
        self,
        *,
        review_id: str,
        target_origin: str,
        kind: str,
        key: str,
        value: object,
        source: str,
        observed_at: datetime,
        receipt_digest: str,
    ) -> Observation:
        return Observation(
            observation_id=self._id_factory("observation"),
            review_id=review_id,
            kind=kind,
            subject=target_origin,
            key=key,
            value=value,
            source=source,
            collector_id=REFERENCE_COLLECTOR_ID,
            collector_version=REFERENCE_COLLECTOR_VERSION,
            observed_at=observed_at,
            receipt_digest=digest(
                {"transport_receipt": receipt_digest, "kind": kind, "key": key}
            ),
        )
