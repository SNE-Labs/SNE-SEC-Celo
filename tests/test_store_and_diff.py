from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from sne_sec_celo.domain import ReviewDiffOutcome, build_review_diff
from sne_sec_celo.errors import ReviewAlreadyExists
from sne_sec_celo.store import SQLiteReviewStore
from tests.helpers import exchange, provider


class StoreAndDiffTests(unittest.IsolatedAsyncioTestCase):
    async def test_store_roundtrip_reproduces_digest_and_rejects_overwrite(self) -> None:
        review = await provider(exchange()).assess("example.org")
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteReviewStore(Path(directory) / "reviews.sqlite3")
            store.initialize()
            store.add(review)
            restored = store.get(review.review_id)
            self.assertEqual(restored.result_digest, review.result_digest)
            with self.assertRaises(ReviewAlreadyExists):
                store.add(review)
            connection = sqlite3.connect(store.database_path)
            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "UPDATE completed_reviews SET provider_id = 'changed' WHERE review_id = ?",
                        (review.review_id,),
                    )
            finally:
                connection.close()

    async def test_rescan_creates_distinct_review_and_resolved_diff(self) -> None:
        assessment = provider(
            exchange(),
            exchange(
                headers=(
                    ("strict-transport-security", "present"),
                    ("content-security-policy", "present"),
                    ("x-content-type-options", "present"),
                    ("referrer-policy", "present"),
                    ("permissions-policy", "present"),
                )
            ),
        )
        before = await assessment.assess("example.org")
        after = await assessment.assess("example.org")
        self.assertNotEqual(before.review_id, after.review_id)
        comparison = build_review_diff(before, after)
        self.assertEqual(
            {item.outcome for item in comparison.entries}, {ReviewDiffOutcome.RESOLVED}
        )


if __name__ == "__main__":
    unittest.main()
