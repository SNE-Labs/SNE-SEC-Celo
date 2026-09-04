from __future__ import annotations

import unittest
from datetime import UTC, datetime

from sne_sec_celo.canonical import canonical_json, digest
from sne_sec_celo.errors import InvariantViolation


class CanonicalTests(unittest.TestCase):
    def test_key_order_is_stable(self) -> None:
        self.assertEqual(canonical_json({"b": 2, "a": 1}), '{"a":1,"b":2}')
        self.assertEqual(digest({"a": 1, "b": 2}), digest({"b": 2, "a": 1}))

    def test_float_and_naive_datetime_are_rejected(self) -> None:
        with self.assertRaises(InvariantViolation):
            canonical_json({"amount": 1.2})
        with self.assertRaises(InvariantViolation):
            canonical_json(datetime(2026, 9, 4))
        self.assertIn("2026-09-04", canonical_json(datetime(2026, 9, 4, tzinfo=UTC)))


if __name__ == "__main__":
    unittest.main()
