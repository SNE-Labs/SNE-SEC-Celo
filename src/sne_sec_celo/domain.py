"""Immutable evidence, rule, Review, and ReviewDiff domain objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from .canonical import digest
from .errors import InvariantViolation


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(StrEnum):
    CERTAIN = "CERTAIN"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"


class RuleOutcome(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


@dataclass(frozen=True)
class Observation:
    observation_id: str
    review_id: str
    kind: str
    subject: str
    key: str
    value: Any
    source: str
    collector_id: str
    collector_version: str
    observed_at: datetime
    receipt_digest: str
    content_digest: str = field(init=False)

    def __post_init__(self) -> None:
        identity = (
            self.observation_id,
            self.review_id,
            self.kind,
            self.subject,
            self.key,
            self.source,
            self.collector_id,
            self.collector_version,
            self.receipt_digest,
        )
        if any(not item.strip() for item in identity):
            raise InvariantViolation("observation identity fields cannot be empty")
        if self.observed_at.tzinfo is None:
            raise InvariantViolation("observation time must be timezone-aware")
        object.__setattr__(self, "content_digest", self.recompute_digest())

    def recompute_digest(self) -> str:
        return digest(
            {
                "observation_id": self.observation_id,
                "review_id": self.review_id,
                "kind": self.kind,
                "subject": self.subject,
                "key": self.key,
                "value": self.value,
                "source": self.source,
                "collector_id": self.collector_id,
                "collector_version": self.collector_version,
                "observed_at": self.observed_at,
                "receipt_digest": self.receipt_digest,
            }
        )


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    review_id: str
    observation_id: str
    observation_digest: str
    kind: str
    subject: str
    admitted_at: datetime
    admission_policy_version: str
    collector_registration_digest: str

    def __post_init__(self) -> None:
        if self.admitted_at.tzinfo is None:
            raise InvariantViolation("evidence admission time must be timezone-aware")


@dataclass(frozen=True)
class RuleReference:
    authority: str
    title: str
    url: str
    version: str | None = None
    control: str | None = None

    def __post_init__(self) -> None:
        if not self.authority.strip() or not self.title.strip():
            raise InvariantViolation("reference authority and title are required")
        if not self.url.startswith(("https://", "http://")):
            raise InvariantViolation("reference URL must be absolute HTTP(S)")


@dataclass(frozen=True)
class RuleEvaluation:
    evaluation_id: str
    review_id: str
    rule_id: str
    rule_version: int
    ruleset_version: str
    outcome: RuleOutcome
    evidence_ids: tuple[str, ...]
    reason_code: str
    evaluated_at: datetime

    def __post_init__(self) -> None:
        if self.evaluated_at.tzinfo is None:
            raise InvariantViolation("evaluation time must be timezone-aware")
        if self.rule_version < 1:
            raise InvariantViolation("rule version must be positive")
        if self.outcome is RuleOutcome.FAIL and not self.evidence_ids:
            raise InvariantViolation("failed evaluation requires admitted evidence")
        if self.outcome in {
            RuleOutcome.NOT_APPLICABLE,
            RuleOutcome.INCONCLUSIVE,
            RuleOutcome.ERROR,
        } and self.evidence_ids:
            raise InvariantViolation("non-decisive evaluation cannot claim evidence")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    review_id: str
    evaluation_id: str
    rule_id: str
    rule_version: int
    title: str
    severity: Severity
    confidence: Confidence
    observation_summary: str
    impact: str
    remediation: str
    verification: str
    evidence_ids: tuple[str, ...]
    references: tuple[RuleReference, ...]

    def __post_init__(self) -> None:
        if not self.evidence_ids:
            raise InvariantViolation("finding requires admitted evidence")
        narratives = (
            self.title,
            self.observation_summary,
            self.impact,
            self.remediation,
            self.verification,
        )
        if any(not value.strip() for value in narratives) or not self.references:
            raise InvariantViolation("finding narrative and references must be complete")


_RISK_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 7,
    Severity.HIGH: 15,
    Severity.CRITICAL: 30,
}


@dataclass(frozen=True)
class CompletedReview:
    review_id: str
    target_origin: str
    provider_id: str
    scanner_version: str
    ruleset_version: str
    requested_at: datetime
    completed_at: datetime
    observations: tuple[Observation, ...]
    evidence: tuple[Evidence, ...]
    evaluations: tuple[RuleEvaluation, ...]
    findings: tuple[Finding, ...]
    score: int = field(init=False)
    result_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if self.requested_at.tzinfo is None or self.completed_at.tzinfo is None:
            raise InvariantViolation("Review times must be timezone-aware")
        if self.completed_at < self.requested_at:
            raise InvariantViolation("Review completion cannot precede its request")
        required = (
            self.review_id,
            self.target_origin,
            self.provider_id,
            self.scanner_version,
            self.ruleset_version,
        )
        if any(not item.strip() for item in required):
            raise InvariantViolation("Review identity fields cannot be empty")

        observations = {item.observation_id: item for item in self.observations}
        evidence = {item.evidence_id: item for item in self.evidence}
        evaluations = {item.evaluation_id: item for item in self.evaluations}
        if len(observations) != len(self.observations):
            raise InvariantViolation("Review contains duplicate observation identities")
        if len(evidence) != len(self.evidence):
            raise InvariantViolation("Review contains duplicate evidence identities")
        if len(evaluations) != len(self.evaluations):
            raise InvariantViolation("Review contains duplicate evaluation identities")

        for item in self.evidence:
            observation = observations.get(item.observation_id)
            if observation is None or observation.review_id != self.review_id:
                raise InvariantViolation(
                    "evidence references a missing or cross-Review observation"
                )
            if item.review_id != self.review_id or item.subject != self.target_origin:
                raise InvariantViolation("evidence subject does not match its Review")
            if item.observation_digest != observation.recompute_digest():
                raise InvariantViolation("evidence references mutated observation content")

        for evaluation in self.evaluations:
            if evaluation.review_id != self.review_id:
                raise InvariantViolation("evaluation belongs to another Review")
            if any(evidence_id not in evidence for evidence_id in evaluation.evidence_ids):
                raise InvariantViolation("evaluation references missing evidence")

        for finding in self.findings:
            related_evaluation = evaluations.get(finding.evaluation_id)
            if finding.review_id != self.review_id or related_evaluation is None:
                raise InvariantViolation("finding references another or missing Review evaluation")
            if related_evaluation.outcome is not RuleOutcome.FAIL:
                raise InvariantViolation("only failed RuleEvaluation may create a Finding")
            if (finding.rule_id, finding.rule_version) != (
                related_evaluation.rule_id,
                related_evaluation.rule_version,
            ):
                raise InvariantViolation("finding and evaluation rule identities differ")
            if set(finding.evidence_ids) != set(related_evaluation.evidence_ids):
                raise InvariantViolation("finding evidence must equal failed evaluation evidence")
            if any(evidence_id not in evidence for evidence_id in finding.evidence_ids):
                raise InvariantViolation("finding references missing evidence")

        risk = sum(_RISK_WEIGHT[item.severity] for item in self.findings)
        score = max(0, 100 - risk)
        object.__setattr__(self, "score", score)
        object.__setattr__(self, "result_digest", self.recompute_digest())

    def recompute_digest(self) -> str:
        return digest(
            {
                "review_id": self.review_id,
                "target_origin": self.target_origin,
                "provider_id": self.provider_id,
                "scanner_version": self.scanner_version,
                "ruleset_version": self.ruleset_version,
                "requested_at": self.requested_at,
                "completed_at": self.completed_at,
                "observations": self.observations,
                "evidence": self.evidence,
                "evaluations": self.evaluations,
                "findings": self.findings,
                "score": self.score,
            }
        )


class ReviewDiffOutcome(StrEnum):
    RESOLVED = "RESOLVED"
    REGRESSED = "REGRESSED"
    UNCHANGED = "UNCHANGED"
    NEW = "NEW"
    COVERAGE_CHANGED = "COVERAGE_CHANGED"


@dataclass(frozen=True)
class ReviewDiffEntry:
    rule_id: str
    outcome: ReviewDiffOutcome
    previous_rule_version: int | None
    current_rule_version: int | None
    previous_outcome: RuleOutcome | None
    current_outcome: RuleOutcome | None


@dataclass(frozen=True)
class ReviewDiff:
    previous_review_id: str
    current_review_id: str
    target_origin: str
    entries: tuple[ReviewDiffEntry, ...]
    diff_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if self.previous_review_id == self.current_review_id:
            raise InvariantViolation("ReviewDiff requires two distinct Reviews")
        if not self.entries:
            raise InvariantViolation("ReviewDiff requires evaluated rule entries")
        object.__setattr__(
            self,
            "diff_digest",
            digest(
                {
                    "previous_review_id": self.previous_review_id,
                    "current_review_id": self.current_review_id,
                    "target_origin": self.target_origin,
                    "entries": self.entries,
                }
            ),
        )


def build_review_diff(previous: CompletedReview, current: CompletedReview) -> ReviewDiff:
    if previous.target_origin != current.target_origin:
        raise InvariantViolation("ReviewDiff requires the same target origin")
    before = {item.rule_id: item for item in previous.evaluations}
    after = {item.rule_id: item for item in current.evaluations}
    if len(before) != len(previous.evaluations) or len(after) != len(current.evaluations):
        raise InvariantViolation("ReviewDiff inputs contain duplicate rule identities")

    entries: list[ReviewDiffEntry] = []
    unknown = {
        RuleOutcome.INCONCLUSIVE,
        RuleOutcome.ERROR,
        RuleOutcome.NOT_APPLICABLE,
    }
    for rule_id in sorted(before.keys() | after.keys()):
        old = before.get(rule_id)
        new = after.get(rule_id)
        if old is None or new is None or old.rule_version != new.rule_version:
            outcome = ReviewDiffOutcome.COVERAGE_CHANGED
        elif old.outcome is RuleOutcome.NOT_APPLICABLE and new.outcome is RuleOutcome.FAIL:
            outcome = ReviewDiffOutcome.NEW
        elif old.outcome in unknown or new.outcome in unknown:
            outcome = ReviewDiffOutcome.COVERAGE_CHANGED
        elif old.outcome is RuleOutcome.FAIL and new.outcome is RuleOutcome.PASS:
            outcome = ReviewDiffOutcome.RESOLVED
        elif old.outcome is RuleOutcome.PASS and new.outcome is RuleOutcome.FAIL:
            outcome = ReviewDiffOutcome.REGRESSED
        elif old.outcome is new.outcome:
            outcome = ReviewDiffOutcome.UNCHANGED
        else:
            raise InvariantViolation("ReviewDiff transition is outside the closed matrix")
        entries.append(
            ReviewDiffEntry(
                rule_id=rule_id,
                outcome=outcome,
                previous_rule_version=old.rule_version if old else None,
                current_rule_version=new.rule_version if new else None,
                previous_outcome=old.outcome if old else None,
                current_outcome=new.outcome if new else None,
            )
        )
    return ReviewDiff(previous.review_id, current.review_id, current.target_origin, tuple(entries))
