from __future__ import annotations

import unittest

from sne_sec_celo.domain import RuleOutcome
from sne_sec_celo.errors import CollectionFailed
from tests.helpers import (
    FakeResolver,
    FakeTransport,
    SequenceClock,
    SequenceIds,
    exchange,
    provider,
)


class ReferenceProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_reference_path_binds_findings_to_evidence(self) -> None:
        assessment = provider(
            exchange(
                headers=(
                    ("strict-transport-security", "max-age=31536000"),
                    ("x-content-type-options", "nosniff"),
                )
            )
        )
        review = await assessment.assess("example.org")

        self.assertEqual(len(review.observations), 6)
        self.assertEqual(len(review.evidence), 6)
        self.assertEqual(len(review.evaluations), 5)
        self.assertEqual(len(review.findings), 3)
        self.assertEqual(review.score, 89)
        evidence_ids = {item.evidence_id for item in review.evidence}
        for finding in review.findings:
            self.assertTrue(set(finding.evidence_ids) <= evidence_ids)
            evaluation = next(
                item for item in review.evaluations if item.evaluation_id == finding.evaluation_id
            )
            self.assertEqual(evaluation.outcome, RuleOutcome.FAIL)

    async def test_redirect_causes_fresh_resolution_and_records_no_query(self) -> None:
        resolver = FakeResolver()
        transport = FakeTransport(
            (
                exchange(302, (("location", "https://next.example.org/final?opaque=value"),)),
                exchange(200),
            )
        )
        from sne_sec_celo.provider import ReferenceAssessmentProvider

        assessment = ReferenceAssessmentProvider(
            resolver=resolver,
            transport=transport,
            clock=SequenceClock(),
            id_factory=SequenceIds(),
        )
        review = await assessment.assess("example.org")
        self.assertEqual(len(resolver.targets), 2)
        redirect = next(item for item in review.observations if item.kind == "HTTP_REDIRECT")
        self.assertNotIn("opaque", redirect.source)
        self.assertNotIn("value", str(redirect.value))

    async def test_ambiguous_redirect_is_not_followed(self) -> None:
        assessment = provider(
            exchange(302, (("location", "https://a.example.org"), ("location", "https://b.example.org")))
        )
        with self.assertRaises(CollectionFailed):
            await assessment.assess("example.org")


if __name__ == "__main__":
    unittest.main()
