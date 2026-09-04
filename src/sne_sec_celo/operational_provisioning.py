"""Crash-aware local provisioning for the hosted Celo agent.

The signing key and facilitator credential live only inside a Windows DPAPI
vault. Railway receives the public identity, the public treasury destination,
and the facilitator credential; it never receives signing authority.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import json
import os
import secrets
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

import httpx

from .canonical import canonical_json
from .errors import InvariantViolation
from .payments import normalize_address

FACILITATOR_PORTAL = "https://x402.celo.org"
VAULT_FORMAT = "sne-sec-celo-operational-secrets-v1"


def _dpapi(data: bytes, *, decrypt: bool) -> bytes:
    if os.name != "nt":
        raise InvariantViolation("operational secret vault requires Windows DPAPI")
    executable = shutil.which("powershell.exe")
    if not executable:
        raise InvariantViolation("Windows PowerShell is required for the DPAPI vault")
    operation = "Unprotect" if decrypt else "Protect"
    script = (
        "$ErrorActionPreference='Stop';"
        "Add-Type -AssemblyName System.Security;"
        "$encoded=[Console]::In.ReadToEnd();"
        "$inputBytes=[Convert]::FromBase64String($encoded);"
        f"$outputBytes=[Security.Cryptography.ProtectedData]::{operation}("
        "$inputBytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);"
        "[Console]::Out.Write([Convert]::ToBase64String($outputBytes))"
    )
    completed = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        check=False,
        input=base64.b64encode(data).decode("ascii"),
        text=True,
    )
    if completed.returncode != 0 or len(completed.stdout) > 16 * 1024 * 1024:
        raise InvariantViolation("Windows DPAPI operation failed")
    try:
        return base64.b64decode(completed.stdout, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InvariantViolation("Windows DPAPI returned malformed output") from exc


def default_vault_path() -> Path:
    root = Path(os.getenv("LOCALAPPDATA", str(Path.home())))
    return root / "SNE-Labs" / "SNE-SEC-Celo" / "operational-secrets.dpapi"


class OperationalSecretVault:
    def __init__(
        self,
        path: Path | None = None,
        *,
        protect: Callable[[bytes], bytes] | None = None,
        unprotect: Callable[[bytes], bytes] | None = None,
    ) -> None:
        self.path = path or default_vault_path()
        self.protect = protect or (lambda value: _dpapi(value, decrypt=False))
        self.unprotect = unprotect or (lambda value: _dpapi(value, decrypt=True))

    def load(self) -> dict[str, object]:
        if not self.path.exists():
            return {"format": VAULT_FORMAT, "identity": {}}
        try:
            value = json.loads(self.unprotect(self.path.read_bytes()).decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InvariantViolation("operational secret vault cannot be decrypted") from exc
        if (
            not isinstance(value, dict)
            or value.get("format") != VAULT_FORMAT
            or not isinstance(value.get("identity"), dict)
        ):
            raise InvariantViolation("operational secret vault is malformed")
        return cast(dict[str, object], value)

    def save(self, value: dict[str, object]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encrypted = self.protect(canonical_json(value).encode("utf-8"))
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_bytes(encrypted)
        with contextlib.suppress(OSError):
            temporary.chmod(0o600)
        os.replace(temporary, self.path)


class FacilitatorKeyIssuer(Protocol):
    def create_key(
        self,
        *,
        address: str,
        private_key: str,
        before_submit: Callable[[], None],
    ) -> tuple[str, str]: ...


class CeloFacilitatorKeyIssuer:
    def __init__(self, base_url: str = FACILITATOR_PORTAL) -> None:
        if base_url.rstrip("/") != FACILITATOR_PORTAL:
            raise InvariantViolation("facilitator provisioning host must be exactly x402.celo.org")
        self.base_url = FACILITATOR_PORTAL

    def create_key(
        self,
        *,
        address: str,
        private_key: str,
        before_submit: Callable[[], None],
    ) -> tuple[str, str]:
        try:
            from eth_account import Account
            from eth_account.messages import encode_defunct
        except ImportError as exc:
            raise InvariantViolation(
                'facilitator provisioning requires: pip install -e ".[wallet-tools]"'
            ) from exc
        with httpx.Client(
            base_url=self.base_url,
            timeout=20,
            follow_redirects=False,
            trust_env=False,
            headers={"Accept": "application/json", "User-Agent": "sne-sec-celo/1.0"},
        ) as client:
            nonce_response = client.get("/api/keys/nonce")
            nonce_response.raise_for_status()
            nonce_value = nonce_response.json()
            nonce = nonce_value.get("nonce") if isinstance(nonce_value, dict) else None
            if not isinstance(nonce, str) or not nonce or len(nonce) > 256:
                raise InvariantViolation("facilitator returned a malformed provisioning nonce")
            message = (
                "x402.celo.org wants you to create an x402 API key.\n\n"
                f"Address: {address}\n"
                f"Nonce: {nonce}\n\n"
                "Signing this message proves you control this wallet. "
                "It costs no gas and sends no transaction."
            )
            signature = Account.sign_message(
                encode_defunct(text=message), private_key=private_key
            ).signature.hex()
            before_submit()
            response = client.post(
                "/api/keys",
                json={"address": address, "nonce": nonce, "signature": signature},
            )
            response.raise_for_status()
            value = response.json()
        api_key = value.get("apiKey") if isinstance(value, dict) else None
        if not isinstance(api_key, str) or not api_key.startswith("x402_") or len(api_key) > 512:
            raise InvariantViolation("facilitator omitted the one-time API credential")
        return api_key, api_key[:12]


def _new_wallet() -> tuple[str, str]:
    try:
        from eth_account import Account
    except ImportError as exc:
        raise InvariantViolation(
            'wallet provisioning requires: pip install -e ".[wallet-tools]"'
        ) from exc
    account = Account.create(extra_entropy=secrets.token_bytes(32))
    return normalize_address(str(account.address)), account.key.hex()


@dataclass(frozen=True)
class ProvisionedOperationalIdentity:
    wallet_address: str
    pay_to: str
    facilitator_key_prefix: str
    vault_path: Path


def provision_operational_identity(
    *,
    pay_to: str,
    vault: OperationalSecretVault | None = None,
    issuer: FacilitatorKeyIssuer | None = None,
) -> ProvisionedOperationalIdentity:
    normalized_pay_to = normalize_address(pay_to)
    vault = vault or OperationalSecretVault()
    issuer = issuer or CeloFacilitatorKeyIssuer()
    state = vault.load()
    raw_identity = state["identity"]
    assert isinstance(raw_identity, dict)

    stored_pay_to = raw_identity.get("pay_to")
    if stored_pay_to is not None and normalize_address(str(stored_pay_to)) != normalized_pay_to:
        raise InvariantViolation("operational vault is already bound to another treasury")
    raw_identity["pay_to"] = normalized_pay_to

    if not raw_identity.get("wallet_address") or not raw_identity.get("wallet_private_key"):
        address, private_key = _new_wallet()
        raw_identity.update(
            {
                "wallet_address": address,
                "wallet_private_key": private_key,
                "facilitator_key_state": "NOT_STARTED",
            }
        )
        vault.save(state)

    key_state = raw_identity.get("facilitator_key_state")
    if key_state in {"IN_FLIGHT", "AMBIGUOUS"} and not raw_identity.get("facilitator_api_key"):
        raise InvariantViolation(
            "facilitator key issuance is ambiguous; reconcile through x402.celo.org"
        )
    if not raw_identity.get("facilitator_api_key"):
        def mark_in_flight() -> None:
            raw_identity["facilitator_key_state"] = "IN_FLIGHT"
            vault.save(state)

        try:
            api_key, prefix = issuer.create_key(
                address=str(raw_identity["wallet_address"]),
                private_key=str(raw_identity["wallet_private_key"]),
                before_submit=mark_in_flight,
            )
        except Exception:
            if raw_identity.get("facilitator_key_state") == "IN_FLIGHT":
                raw_identity["facilitator_key_state"] = "AMBIGUOUS"
                vault.save(state)
            raise
        raw_identity.update(
            {
                "facilitator_api_key": api_key,
                "facilitator_key_prefix": prefix,
                "facilitator_key_state": "ISSUED",
            }
        )
        vault.save(state)

    return ProvisionedOperationalIdentity(
        wallet_address=normalize_address(str(raw_identity["wallet_address"])),
        pay_to=normalized_pay_to,
        facilitator_key_prefix=str(raw_identity["facilitator_key_prefix"]),
        vault_path=vault.path,
    )


def publish_to_railway(
    identity: ProvisionedOperationalIdentity,
    *,
    vault: OperationalSecretVault,
    repository: Path,
    enable: bool,
) -> None:
    executable = shutil.which("railway.cmd" if os.name == "nt" else "railway")
    if not executable:
        raise InvariantViolation("Railway CLI was not found")
    state = vault.load()
    raw_identity = state["identity"]
    assert isinstance(raw_identity, dict)
    api_key = raw_identity.get("facilitator_api_key")
    if not isinstance(api_key, str) or not api_key:
        raise InvariantViolation("vault has no facilitator credential to publish")
    values = (
        ("SNE_SEC_CELO_AGENT_WALLET", identity.wallet_address),
        ("SNE_SEC_CELO_X402_PAY_TO", identity.pay_to),
        ("SNE_SEC_CELO_X402_API_KEY", api_key),
    )
    for key, value in values:
        _set_railway_variable(executable, repository, key, value, skip_deploys=True)
    if enable:
        _set_railway_variable(
            executable,
            repository,
            "SNE_SEC_CELO_X402_ENABLED",
            "true",
            skip_deploys=False,
        )


def _set_railway_variable(
    executable: str, repository: Path, key: str, value: str, *, skip_deploys: bool
) -> None:
    command = [executable, "variable", "set", key, "--stdin", "--json"]
    if skip_deploys:
        command.append("--skip-deploys")
    completed = subprocess.run(
        command,
        input=value,
        text=True,
        capture_output=True,
        check=False,
        cwd=repository,
    )
    if completed.returncode != 0:
        raise InvariantViolation(f"Railway rejected variable {key}")


def safe_summary(identity: ProvisionedOperationalIdentity) -> dict[str, object]:
    return {
        "network": "eip155:42220",
        "identity_wallet": identity.wallet_address,
        "x402_pay_to": identity.pay_to,
        "facilitator_key_prefix": identity.facilitator_key_prefix,
        "vault_path": str(identity.vault_path),
        "signing_key_exposed": False,
        "facilitator_key_exposed": False,
    }


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Provision the hosted Celo agent with a local DPAPI identity vault."
    )
    parser.add_argument("--pay-to", required=True, help="existing Celo treasury address")
    parser.add_argument("--vault", type=Path, default=default_vault_path())
    parser.add_argument("--railway", action="store_true")
    parser.add_argument("--enable", action="store_true")
    arguments = parser.parse_args()
    if arguments.enable and not arguments.railway:
        raise SystemExit("--enable requires --railway")
    vault = OperationalSecretVault(arguments.vault)
    try:
        identity = provision_operational_identity(pay_to=arguments.pay_to, vault=vault)
        if arguments.railway:
            publish_to_railway(
                identity,
                vault=vault,
                repository=_repository_root(),
                enable=arguments.enable,
            )
    except (httpx.HTTPError, InvariantViolation, OSError) as exc:
        raise SystemExit(str(exc)) from None
    print(canonical_json(safe_summary(identity)))


if __name__ == "__main__":
    main()
