# SNE-SEC Celo Agent

SNE-SEC Celo Agent is the open source agent, payment, settlement and evidence protocol for evidence-backed security assessments. SNE Labs operates a separate proprietary assessment provider, while this repository includes an executable reference provider.

The public protocol owns the independently inspectable path from an agent request through payment
admission, entitlement, evidence binding, immutable review, rescan, and measurable ReviewDiff.
The production assessment engine operated by SNE Labs is a separate provider with broader
collector and ruleset coverage.

## Constitutional boundary

```text
PUBLIC SNE-SEC CELO AGENT
agent identity → payment requirement → settlement evidence → entitlement
               → assessment provider contract → evidence-bound Review
               → rescan → ReviewDiff

ASSESSMENT PROVIDERS
├── executable Apache-2.0 reference provider (this repository)
└── proprietary SNE Labs provider (separate operated service)
```

The hosted provider is not required to clone, test, run, or inspect the reference path. The public
repository is not a forwarding shell around a private API.

## Current work

The repository is being built during the Celo Agents at Work hackathon. Every capability lands as
a reviewable commit with tests and, where an external effect exists, a separately recorded witness.
No testnet or simulated transaction is presented as mainnet adoption evidence.

## Run the reference provider

Python 3.12 or newer is required.

```powershell
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
$env:PYTHONPATH = "src"
& .\.venv\Scripts\sne-sec-celo.exe --database .\reviews.sqlite3 review https://celo.org --output .\review.json
```

This performs a real HTTPS assessment using a DNS- and peer-pinned transport. It records only
bounded response metadata and presence facts for five security headers; response bodies, cookies,
credentials, and redirect query strings do not enter Evidence.

Run the API:

```powershell
$env:SNE_SEC_CELO_DATABASE = ".\reviews.sqlite3"
& .\.venv\Scripts\uvicorn.exe sne_sec_celo.api:app --host 127.0.0.1 --port 8000
```

The reference surface exposes:

```text
GET  /healthz
POST /v1/reference/reviews
GET  /v1/reviews/{review_id}
POST /v1/review-diffs
GET  /.well-known/agent.json
GET  /.well-known/sne-sec-capabilities.json
```

Every persisted Review is append-only at the database boundary. Rescanning creates another Review
and `ReviewDiff` classifies resolution, regression, unchanged results, and coverage changes.

## Provision the dedicated Celo wallet

The agent identity and x402 `payTo` wallet is a dedicated Celo mainnet address. Provision it on an
operator-controlled machine; never put its password, private key, or encrypted keystore in this
repository or in the API deployment.

```powershell
& .\.venv\Scripts\python.exe -m pip install -e ".[wallet-tools]"
& .\.venv\Scripts\sne-sec-celo-provision-wallet.exe `
    --output "$env:USERPROFILE\Documents\SNE-SEC-Celo-Wallet-Backup"

& .\.venv\Scripts\sne-sec-celo-verify-wallet.exe `
    --bundle "$env:USERPROFILE\Documents\SNE-SEC-Celo-Wallet-Backup"
```

Both commands prompt for the password without accepting it as an argument or environment variable.
The bundle contains one encrypted Web3 keystore, a public manifest bound to `eip155:42220`, and
backup instructions. Only the public address and public manifest are admissible for registration.

## Hosted agent URI

The public reference agent is deployed from this repository at:

```text
https://sne-sec-celo-agent-production.up.railway.app/.well-known/agent.json
```

The Railway service uses the repository Dockerfile, a persistent `/data` volume for append-only
reference Reviews, and `/healthz` as its deployment gate. Wallet private material is never present
in the service.

## Verify

```powershell
& .\scripts\verify.ps1
python scripts\witness_reference_path.py https://celo.org
docker build -t sne-sec-celo .
```

See [the public/private boundary](docs/architecture/public-private-boundary.md) and
[the constitution](CONSTITUTION.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
