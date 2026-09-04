"""Offline provisioning for the dedicated Celo agent and x402 payTo wallet.

This module is not imported by API or assessment runtime paths. Private key
material exists only in process memory until it is encrypted as a Web3 keystore.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import importlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

from .canonical import canonical_json, digest

CELO_MAINNET_CAIP2 = "eip155:42220"


class _AccountValue(Protocol):
    address: str
    key: bytes


class _AccountAPI(Protocol):
    def create(self, extra_entropy: bytes) -> _AccountValue: ...

    def encrypt(self, private_key: bytes, password: str) -> dict[str, Any]: ...

    def decrypt(self, keystore: dict[str, Any], password: str) -> bytes: ...

    def from_key(self, private_key: bytes) -> _AccountValue: ...


@dataclass(frozen=True)
class ProvisionedWallet:
    address: str
    output_directory: Path
    public_manifest_digest: str


def _account_api() -> _AccountAPI:
    try:
        module = importlib.import_module("eth_account")
    except ImportError as exc:
        raise RuntimeError(
            "install wallet tooling with: python -m pip install -e .[wallet-tools]"
        ) from exc
    return cast(_AccountAPI, module.Account)


def _write_exclusive_json(path: Path, value: object) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(canonical_json(value))
        stream.write("\n")


def _read_small_object(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError(f"wallet bundle file is absent or oversized: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"wallet bundle file is malformed: {path.name}")
    return cast(dict[str, Any], value)


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def provision_celo_wallet(
    *, output_directory: Path, password: str, forbidden_root: Path
) -> ProvisionedWallet:
    if len(password) < 16:
        raise ValueError("keystore password must contain at least 16 characters")
    destination = output_directory.expanduser().resolve()
    repository = forbidden_root.resolve()
    if destination == repository or repository in destination.parents:
        raise ValueError("wallet material must be generated outside the repository")
    if destination.anchor and not Path(destination.anchor).exists():
        raise ValueError(f"wallet output drive does not exist: {destination.anchor}")
    if destination.exists():
        raise FileExistsError("wallet output directory must not already exist")

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(mode=0o700)
    account_api = _account_api()
    account = account_api.create(secrets.token_bytes(32))
    keystore = account_api.encrypt(account.key, password)
    keystore_path = destination / "celo-agent-keystore.json"
    _write_exclusive_json(keystore_path, keystore)

    public_record = {
        "version": 1,
        "role": "SNE_SEC_CELO_AGENT_AND_X402_PAY_TO",
        "network": CELO_MAINNET_CAIP2,
        "address": str(account.address),
        "created_at": datetime.now(UTC),
        "keystore": {
            "format": "web3-secret-storage-v3",
            "filename": keystore_path.name,
            "content_digest": _sha256_file(keystore_path),
        },
        "operational_boundary": {
            "api_has_signing_authority": False,
            "assessment_provider_has_signing_authority": False,
            "private_key_may_be_uploaded": False,
            "outbound_treasury_collection": "NOT_ADMITTED",
        },
    }
    manifest_digest = digest(public_record)
    public_manifest = {**public_record, "manifest_digest": manifest_digest}
    _write_exclusive_json(destination / "celo-agent-public-manifest.json", public_manifest)
    _write_exclusive_json(
        destination / "BACKUP-INSTRUCTIONS.json",
        {
            "version": 1,
            "instructions": [
                "Back up this encrypted directory and the password separately.",
                "Never commit or upload the encrypted keystore to the application runtime.",
                "Verify the backup with sne-sec-celo-verify-wallet before registration.",
            ],
        },
    )
    return ProvisionedWallet(str(account.address), destination, manifest_digest)


def verify_celo_wallet(*, bundle_directory: Path, password: str) -> ProvisionedWallet:
    bundle = bundle_directory.expanduser().resolve()
    if not bundle.is_dir():
        raise ValueError("wallet backup directory does not exist")
    manifest = _read_small_object(bundle / "celo-agent-public-manifest.json")
    keystore_path = bundle / "celo-agent-keystore.json"
    keystore = _read_small_object(keystore_path)
    keystore_claim = manifest.get("keystore")
    if not isinstance(keystore_claim, dict):
        raise ValueError("wallet public manifest has no keystore identity")
    if keystore_claim.get("content_digest") != _sha256_file(keystore_path):
        raise ValueError("encrypted keystore digest does not match the public manifest")

    claimed_digest = manifest.pop("manifest_digest", None)
    if not isinstance(claimed_digest, str) or claimed_digest != digest(manifest):
        raise ValueError("wallet public manifest digest does not reproduce")
    if manifest.get("network") != CELO_MAINNET_CAIP2:
        raise ValueError("wallet public manifest is not admitted for Celo mainnet")

    try:
        account_api = _account_api()
        private_key = account_api.decrypt(keystore, password)
        derived_address = str(account_api.from_key(private_key).address)
    except Exception as exc:
        raise ValueError("wallet backup decryption failed") from exc
    claimed_address = manifest.get("address")
    if not isinstance(claimed_address, str) or claimed_address.lower() != derived_address.lower():
        raise ValueError("decrypted wallet does not match the public manifest")
    return ProvisionedWallet(derived_address, bundle, claimed_digest)


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Provision the encrypted SNE-SEC Celo agent/payTo wallet offline."
    )
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    requested = arguments.output.expanduser()
    if requested.anchor and not Path(requested.anchor).exists():
        raise SystemExit(f"output drive does not exist: {requested.anchor}")
    password = getpass.getpass("New keystore password: ")
    confirmation = getpass.getpass("Repeat keystore password: ")
    if password != confirmation:
        raise SystemExit("passwords do not match")
    try:
        wallet = provision_celo_wallet(
            output_directory=arguments.output,
            password=password,
            forbidden_root=_repository_root(),
        )
    except (FileExistsError, RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from None
    print(f"Encrypted Celo agent wallet created in {wallet.output_directory}")
    print(f"Celo agent/payTo address: {wallet.address}")
    print("No private key was printed. Keep the encrypted bundle and password separate.")


def verify_main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify the SNE-SEC Celo wallet backup without exposing private material."
    )
    parser.add_argument("--bundle", type=Path, required=True)
    arguments = parser.parse_args()
    password = getpass.getpass("Keystore password: ")
    try:
        wallet = verify_celo_wallet(bundle_directory=arguments.bundle, password=password)
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from None
    print(f"Celo wallet backup verified: {wallet.output_directory}")
    print(f"Celo agent/payTo address: {wallet.address}")
    print("The encrypted keystore matches the public manifest. No private key was printed.")


if __name__ == "__main__":
    main()
