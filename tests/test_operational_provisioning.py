from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sne_sec_celo.errors import InvariantViolation
from sne_sec_celo.operational_provisioning import (
    OperationalSecretVault,
    provision_operational_identity,
    safe_summary,
)

TREASURY = "0x34385Fc3B012Ae8980e17F6c3224a5aE0f946289"
IDENTITY = "0x1111111111111111111111111111111111111111"


class FakeIssuer:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def create_key(
        self, *, address: str, private_key: str, before_submit: object
    ) -> tuple[str, str]:
        self.calls += 1
        assert callable(before_submit)
        before_submit()
        if self.fail:
            raise TimeoutError("result was not observed")
        self.last_address = address
        self.last_private_key = private_key
        return "x402_test_credential", "x402_test_cr"


class OperationalProvisioningTests(unittest.TestCase):
    def vault(self, root: str) -> OperationalSecretVault:
        return OperationalSecretVault(
            Path(root) / "vault.dpapi",
            protect=lambda value: b"sealed:" + value,
            unprotect=lambda value: value.removeprefix(b"sealed:"),
        )

    def test_identity_and_facilitator_key_are_provisioned_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            vault = self.vault(temporary)
            issuer = FakeIssuer()
            with patch(
                "sne_sec_celo.operational_provisioning._new_wallet",
                return_value=(IDENTITY, "private-material"),
            ) as wallet:
                first = provision_operational_identity(
                    pay_to=TREASURY, vault=vault, issuer=issuer
                )
                second = provision_operational_identity(
                    pay_to=TREASURY, vault=vault, issuer=issuer
                )
            self.assertEqual(first, second)
            self.assertEqual(wallet.call_count, 1)
            self.assertEqual(issuer.calls, 1)
            rendered = str(safe_summary(first))
            self.assertNotIn("private-material", rendered)
            self.assertNotIn("x402_test_credential", rendered)
            self.assertEqual(first.pay_to, TREASURY.lower())

    def test_ambiguous_issuance_is_durable_and_not_retried(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            vault = self.vault(temporary)
            issuer = FakeIssuer(fail=True)
            with patch(
                "sne_sec_celo.operational_provisioning._new_wallet",
                return_value=(IDENTITY, "private-material"),
            ):
                with self.assertRaises(TimeoutError):
                    provision_operational_identity(
                        pay_to=TREASURY, vault=vault, issuer=issuer
                    )
                with self.assertRaisesRegex(InvariantViolation, "ambiguous"):
                    provision_operational_identity(
                        pay_to=TREASURY, vault=vault, issuer=issuer
                    )
            self.assertEqual(issuer.calls, 1)

    def test_vault_cannot_be_rebound_to_another_treasury(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            vault = self.vault(temporary)
            with patch(
                "sne_sec_celo.operational_provisioning._new_wallet",
                return_value=(IDENTITY, "private-material"),
            ):
                provision_operational_identity(
                    pay_to=TREASURY, vault=vault, issuer=FakeIssuer()
                )
            with self.assertRaisesRegex(InvariantViolation, "another treasury"):
                provision_operational_identity(
                    pay_to="0x2222222222222222222222222222222222222222",
                    vault=vault,
                    issuer=FakeIssuer(),
                )


if __name__ == "__main__":
    unittest.main()
