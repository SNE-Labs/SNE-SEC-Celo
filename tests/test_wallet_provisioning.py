from __future__ import annotations

import json
import secrets
import tempfile
import unittest
from pathlib import Path

from sne_sec_celo.wallet_provisioning import provision_celo_wallet, verify_celo_wallet


class WalletProvisioningTests(unittest.TestCase):
    def test_bundle_is_encrypted_bound_and_created_outside_repository(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        password = secrets.token_urlsafe(24)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "wallet-backup"
            generated = provision_celo_wallet(
                output_directory=destination,
                password=password,
                forbidden_root=repository,
            )
            self.assertEqual(
                {path.name for path in destination.iterdir()},
                {
                    "BACKUP-INSTRUCTIONS.json",
                    "celo-agent-keystore.json",
                    "celo-agent-public-manifest.json",
                },
            )
            keystore = json.loads(
                (destination / "celo-agent-keystore.json").read_text(encoding="utf-8")
            )
            self.assertEqual(keystore["version"], 3)
            self.assertIn("crypto", keystore)
            self.assertNotIn("private_key", keystore)
            manifest = json.loads(
                (destination / "celo-agent-public-manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["network"], "eip155:42220")
            self.assertEqual(manifest["address"], generated.address)
            verified = verify_celo_wallet(bundle_directory=destination, password=password)
            self.assertEqual(verified, generated)
            with self.assertRaises(ValueError):
                verify_celo_wallet(
                    bundle_directory=destination,
                    password=secrets.token_urlsafe(24),
                )

    def test_repository_and_existing_destination_are_rejected(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        password = secrets.token_urlsafe(24)
        with self.assertRaises(ValueError):
            provision_celo_wallet(
                output_directory=repository / "wallet",
                password=password,
                forbidden_root=repository,
            )
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(FileExistsError):
            provision_celo_wallet(
                output_directory=Path(temporary),
                password=password,
                forbidden_root=repository,
            )


if __name__ == "__main__":
    unittest.main()
