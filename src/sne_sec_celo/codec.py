"""Lossless JSON codec for immutable Reviews."""

from __future__ import annotations

import json
from typing import Any, cast

from .canonical import canonical_json, parse_utc
from .domain import (
    CompletedReview,
    Confidence,
    Evidence,
    Finding,
    Observation,
    RuleEvaluation,
    RuleOutcome,
    RuleReference,
    Severity,
)
from .errors import InvariantViolation


def review_to_json(review: CompletedReview) -> str:
    return canonical_json(review)


def review_from_json(payload: str) -> CompletedReview:
    try:
        raw = cast(dict[str, Any], json.loads(payload))
        observations = tuple(_observation(item) for item in raw["observations"])
        evidence = tuple(_evidence(item) for item in raw["evidence"])
        evaluations = tuple(_evaluation(item) for item in raw["evaluations"])
        findings = tuple(_finding(item) for item in raw["findings"])
        review = CompletedReview(
            review_id=str(raw["review_id"]),
            target_origin=str(raw["target_origin"]),
            provider_id=str(raw["provider_id"]),
            scanner_version=str(raw["scanner_version"]),
            ruleset_version=str(raw["ruleset_version"]),
            requested_at=parse_utc(str(raw["requested_at"])),
            completed_at=parse_utc(str(raw["completed_at"])),
            observations=observations,
            evidence=evidence,
            evaluations=evaluations,
            findings=findings,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise InvariantViolation("stored Review payload has an invalid shape") from exc
    if int(raw.get("score", -1)) != review.score:
        raise InvariantViolation("stored Review score does not reproduce")
    if str(raw.get("result_digest", "")) != review.result_digest:
        raise InvariantViolation("stored Review digest does not reproduce")
    return review


def _observation(value: object) -> Observation:
    raw = cast(dict[str, Any], value)
    observation = Observation(
        observation_id=str(raw["observation_id"]),
        review_id=str(raw["review_id"]),
        kind=str(raw["kind"]),
        subject=str(raw["subject"]),
        key=str(raw["key"]),
        value=raw["value"],
        source=str(raw["source"]),
        collector_id=str(raw["collector_id"]),
        collector_version=str(raw["collector_version"]),
        observed_at=parse_utc(str(raw["observed_at"])),
        receipt_digest=str(raw["receipt_digest"]),
    )
    if str(raw.get("content_digest", "")) != observation.content_digest:
        raise InvariantViolation("stored observation digest does not reproduce")
    return observation


def _evidence(value: object) -> Evidence:
    raw = cast(dict[str, Any], value)
    return Evidence(
        evidence_id=str(raw["evidence_id"]),
        review_id=str(raw["review_id"]),
        observation_id=str(raw["observation_id"]),
        observation_digest=str(raw["observation_digest"]),
        kind=str(raw["kind"]),
        subject=str(raw["subject"]),
        admitted_at=parse_utc(str(raw["admitted_at"])),
        admission_policy_version=str(raw["admission_policy_version"]),
        collector_registration_digest=str(raw["collector_registration_digest"]),
    )


def _evaluation(value: object) -> RuleEvaluation:
    raw = cast(dict[str, Any], value)
    return RuleEvaluation(
        evaluation_id=str(raw["evaluation_id"]),
        review_id=str(raw["review_id"]),
        rule_id=str(raw["rule_id"]),
        rule_version=int(raw["rule_version"]),
        ruleset_version=str(raw["ruleset_version"]),
        outcome=RuleOutcome(str(raw["outcome"])),
        evidence_ids=tuple(str(item) for item in raw["evidence_ids"]),
        reason_code=str(raw["reason_code"]),
        evaluated_at=parse_utc(str(raw["evaluated_at"])),
    )


def _finding(value: object) -> Finding:
    raw = cast(dict[str, Any], value)
    references = tuple(
        RuleReference(
            authority=str(item["authority"]),
            title=str(item["title"]),
            url=str(item["url"]),
            version=str(item["version"]) if item.get("version") else None,
            control=str(item["control"]) if item.get("control") else None,
        )
        for item in raw["references"]
    )
    return Finding(
        finding_id=str(raw["finding_id"]),
        review_id=str(raw["review_id"]),
        evaluation_id=str(raw["evaluation_id"]),
        rule_id=str(raw["rule_id"]),
        rule_version=int(raw["rule_version"]),
        title=str(raw["title"]),
        severity=Severity(str(raw["severity"])),
        confidence=Confidence(str(raw["confidence"])),
        observation_summary=str(raw["observation_summary"]),
        impact=str(raw["impact"]),
        remediation=str(raw["remediation"]),
        verification=str(raw["verification"]),
        evidence_ids=tuple(str(item) for item in raw["evidence_ids"]),
        references=references,
    )
