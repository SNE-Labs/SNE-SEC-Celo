"""Commercially safe public projections for Reviews and ReviewDiffs."""

from __future__ import annotations

from .domain import CompletedReview, ReviewDiff, ReviewDiffOutcome, Severity


def review_preview(review: CompletedReview) -> dict[str, object]:
    """Project a Review without evidence, rules, findings, or remediation text."""
    severity_counts = {
        severity.value: sum(1 for finding in review.findings if finding.severity is severity)
        for severity in Severity
    }
    populated = [severity for severity in Severity if severity_counts[severity.value] > 0]
    return {
        "review_id": review.review_id,
        "status": "COMPLETED",
        "score": review.score,
        "summary": {
            "finding_count": len(review.findings),
            "highest_severity": populated[-1].value if populated else None,
            "severity_counts": severity_counts,
        },
    }


def review_diff_preview(comparison: ReviewDiff) -> dict[str, object]:
    """Project a ReviewDiff without rule identities, versions, or outcomes by rule."""
    outcome_counts = {
        outcome.value: sum(1 for entry in comparison.entries if entry.outcome is outcome)
        for outcome in ReviewDiffOutcome
    }
    return {
        "previous_review_id": comparison.previous_review_id,
        "current_review_id": comparison.current_review_id,
        "status": "COMPLETED",
        "summary": {
            "evaluated_rule_count": len(comparison.entries),
            "outcome_counts": outcome_counts,
        },
    }
