"""Closed declarative ruleset loader and deterministic RuleEvaluation engine."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files

from .domain import (
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


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    version: int
    title: str
    observation_kind: str
    observation_key: str
    expected_present: bool
    severity: Severity
    confidence: Confidence
    observation_summary: str
    impact: str
    remediation: str
    verification: str
    references: tuple[RuleReference, ...]
    required_scheme: str | None = None


@dataclass(frozen=True)
class RuleSet:
    version: str
    rules: tuple[RuleDefinition, ...]

    def __post_init__(self) -> None:
        identities = {(rule.rule_id, rule.version) for rule in self.rules}
        if not self.version or not self.rules or len(identities) != len(self.rules):
            raise InvariantViolation("ruleset identity is empty or contains duplicate rules")


def load_reference_ruleset() -> RuleSet:
    resource = files("sne_sec_celo.rulesets").joinpath("reference-2026.09.1.json")
    payload = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("rules"), list):
        raise InvariantViolation("reference ruleset has an invalid root shape")
    rules: list[RuleDefinition] = []
    for raw in payload["rules"]:
        if not isinstance(raw, dict):
            raise InvariantViolation("reference ruleset contains a malformed rule")
        references_raw = raw.get("references")
        if not isinstance(references_raw, list):
            raise InvariantViolation("rule references must be a list")
        if not all(isinstance(item, dict) for item in references_raw):
            raise InvariantViolation("rule contains a malformed structured reference")
        if not isinstance(raw.get("expected_present"), bool):
            raise InvariantViolation("expected_present must be a boolean")
        references = tuple(
            RuleReference(
                authority=str(item["authority"]),
                title=str(item["title"]),
                url=str(item["url"]),
                version=str(item["version"]) if item.get("version") else None,
                control=str(item["control"]) if item.get("control") else None,
            )
            for item in references_raw
        )
        rules.append(
            RuleDefinition(
                rule_id=str(raw["id"]),
                version=int(raw["version"]),
                title=str(raw["title"]),
                observation_kind=str(raw["observation_kind"]),
                observation_key=str(raw["observation_key"]),
                expected_present=raw["expected_present"],
                severity=Severity(str(raw["severity"])),
                confidence=Confidence(str(raw["confidence"])),
                observation_summary=str(raw["observation_summary"]),
                impact=str(raw["impact"]),
                remediation=str(raw["remediation"]),
                verification=str(raw["verification"]),
                references=references,
                required_scheme=(
                    str(raw["required_scheme"]) if raw.get("required_scheme") else None
                ),
            )
        )
    return RuleSet(str(payload["version"]), tuple(rules))


class RuleEngine:
    def __init__(self, ruleset: RuleSet) -> None:
        self.ruleset = ruleset

    def evaluate_all(
        self,
        *,
        review_id: str,
        scheme: str,
        observations: tuple[Observation, ...],
        evidence: tuple[Evidence, ...],
        evaluated_at: datetime,
        id_factory: Callable[[str], str],
    ) -> tuple[tuple[RuleEvaluation, ...], tuple[Finding, ...]]:
        observation_by_id = {item.observation_id: item for item in observations}
        evidence_by_observation: dict[str, Evidence] = {}
        for item in evidence:
            observation = observation_by_id.get(item.observation_id)
            if observation is None or item.review_id != review_id:
                raise InvariantViolation("rule engine received missing or cross-Review evidence")
            if item.observation_digest != observation.recompute_digest():
                raise InvariantViolation("rule engine received mutated observation content")
            evidence_by_observation[item.observation_id] = item

        evaluations: list[RuleEvaluation] = []
        findings: list[Finding] = []
        for rule in self.ruleset.rules:
            evaluation, finding = self._evaluate_one(
                rule=rule,
                review_id=review_id,
                scheme=scheme,
                observations=observations,
                evidence_by_observation=evidence_by_observation,
                evaluated_at=evaluated_at,
                id_factory=id_factory,
            )
            evaluations.append(evaluation)
            if finding is not None:
                findings.append(finding)
        return tuple(evaluations), tuple(findings)

    def _evaluate_one(
        self,
        *,
        rule: RuleDefinition,
        review_id: str,
        scheme: str,
        observations: tuple[Observation, ...],
        evidence_by_observation: Mapping[str, Evidence],
        evaluated_at: datetime,
        id_factory: Callable[[str], str],
    ) -> tuple[RuleEvaluation, Finding | None]:
        if rule.required_scheme is not None and scheme != rule.required_scheme:
            return self._without_finding(
                rule, review_id, RuleOutcome.NOT_APPLICABLE, "SCHEME_NOT_APPLICABLE",
                evaluated_at, id_factory,
            )
        matches = tuple(
            item
            for item in observations
            if item.kind == rule.observation_kind and item.key == rule.observation_key
        )
        if not matches:
            return self._without_finding(
                rule, review_id, RuleOutcome.INCONCLUSIVE, "REQUIRED_OBSERVATION_MISSING",
                evaluated_at, id_factory,
            )
        if len(matches) != 1:
            return self._without_finding(
                rule, review_id, RuleOutcome.ERROR, "AMBIGUOUS_OBSERVATION",
                evaluated_at, id_factory,
            )
        observation = matches[0]
        admitted = evidence_by_observation.get(observation.observation_id)
        if admitted is None:
            raise InvariantViolation("matched observation has not been admitted as evidence")
        if not isinstance(observation.value, dict) or not isinstance(
            observation.value.get("present"), bool
        ):
            return self._without_finding(
                rule, review_id, RuleOutcome.ERROR, "OBSERVATION_SHAPE_INVALID",
                evaluated_at, id_factory,
            )

        passed = observation.value["present"] is rule.expected_present
        outcome = RuleOutcome.PASS if passed else RuleOutcome.FAIL
        evaluation = RuleEvaluation(
            evaluation_id=id_factory("eval"),
            review_id=review_id,
            rule_id=rule.rule_id,
            rule_version=rule.version,
            ruleset_version=self.ruleset.version,
            outcome=outcome,
            evidence_ids=(admitted.evidence_id,),
            reason_code="ASSERTION_SATISFIED" if passed else "ASSERTION_FAILED",
            evaluated_at=evaluated_at,
        )
        if passed:
            return evaluation, None
        finding = Finding(
            finding_id=id_factory("finding"),
            review_id=review_id,
            evaluation_id=evaluation.evaluation_id,
            rule_id=rule.rule_id,
            rule_version=rule.version,
            title=rule.title,
            severity=rule.severity,
            confidence=rule.confidence,
            observation_summary=rule.observation_summary,
            impact=rule.impact,
            remediation=rule.remediation,
            verification=rule.verification,
            evidence_ids=evaluation.evidence_ids,
            references=rule.references,
        )
        return evaluation, finding

    def _without_finding(
        self,
        rule: RuleDefinition,
        review_id: str,
        outcome: RuleOutcome,
        reason_code: str,
        evaluated_at: datetime,
        id_factory: Callable[[str], str],
    ) -> tuple[RuleEvaluation, None]:
        return RuleEvaluation(
            evaluation_id=id_factory("eval"),
            review_id=review_id,
            rule_id=rule.rule_id,
            rule_version=rule.version,
            ruleset_version=self.ruleset.version,
            outcome=outcome,
            evidence_ids=(),
            reason_code=reason_code,
            evaluated_at=evaluated_at,
        ), None
