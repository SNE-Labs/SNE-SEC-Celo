"""Admission boundary between collector output and rule-consumable Evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .canonical import digest
from .domain import Evidence, Observation
from .errors import InvariantViolation


@dataclass(frozen=True)
class CollectorRegistration:
    collector_id: str
    collector_version: str
    allowed_kinds: frozenset[str]

    @property
    def registration_digest(self) -> str:
        return digest(
            {
                "collector_id": self.collector_id,
                "collector_version": self.collector_version,
                "allowed_kinds": sorted(self.allowed_kinds),
            }
        )


class EvidenceAdmissionPolicy:
    version = "sne-sec-celo-evidence-admission-1"

    def __init__(self, registrations: tuple[CollectorRegistration, ...]) -> None:
        self._registrations = {
            (registration.collector_id, registration.collector_version): registration
            for registration in registrations
        }
        if len(self._registrations) != len(registrations):
            raise InvariantViolation("collector registry contains duplicate identities")

    def admit(
        self,
        observation: Observation,
        *,
        review_id: str,
        target_origin: str,
        evidence_id: str,
        admitted_at: datetime,
    ) -> Evidence:
        if observation.review_id != review_id:
            raise InvariantViolation("observation belongs to another Review")
        if observation.subject != target_origin:
            raise InvariantViolation("observation subject differs from Review target")
        registration = self._registrations.get(
            (observation.collector_id, observation.collector_version)
        )
        if registration is None:
            raise InvariantViolation("collector identity and version are not registered")
        if observation.kind not in registration.allowed_kinds:
            raise InvariantViolation("collector is not admitted for this observation kind")
        if admitted_at.tzinfo is None:
            raise InvariantViolation("evidence admission time must be timezone-aware")
        return Evidence(
            evidence_id=evidence_id,
            review_id=review_id,
            observation_id=observation.observation_id,
            observation_digest=observation.content_digest,
            kind=observation.kind,
            subject=observation.subject,
            admitted_at=admitted_at,
            admission_policy_version=self.version,
            collector_registration_digest=registration.registration_digest,
        )
