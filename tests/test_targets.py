from __future__ import annotations

import unittest

from sne_sec_celo.errors import TargetRejected
from sne_sec_celo.targets import (
    admit_resolution,
    normalize_origin,
    normalize_redirect,
    validate_connected_peer,
    validate_public_ip,
)


class TargetAdmissionTests(unittest.TestCase):
    def test_origin_is_https_and_discards_user_path(self) -> None:
        target = normalize_origin("http://EXAMPLE.org/private?token=not-recorded")
        self.assertEqual(target.url, "https://example.org/")

    def test_private_and_special_destinations_fail_closed(self) -> None:
        for value in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "192.0.2.1"):
            with self.subTest(value=value), self.assertRaises(TargetRejected):
                validate_public_ip(value)
        for value in ("localhost", "service.internal", "example.test"):
            with self.subTest(value=value), self.assertRaises(TargetRejected):
                normalize_origin(value)

    def test_one_unsafe_dns_answer_rejects_entire_resolution(self) -> None:
        target = normalize_origin("example.org")
        with self.assertRaises(TargetRejected):
            admit_resolution(target, ("93.184.216.34", "127.0.0.1"))

    def test_peer_must_belong_to_admitted_dns_answers(self) -> None:
        resolution = admit_resolution(normalize_origin("example.org"), ("93.184.216.34",))
        with self.assertRaises(TargetRejected):
            validate_connected_peer("8.8.8.8", resolution)

    def test_redirect_is_reparsed_and_query_is_not_public_source(self) -> None:
        target = normalize_redirect(
            "https://www.example.org/next?opaque=value", base_url="https://example.org/"
        )
        self.assertEqual(target.url, "https://www.example.org/next?opaque=value")
        self.assertEqual(target.public_source, "https://www.example.org/next")


if __name__ == "__main__":
    unittest.main()
