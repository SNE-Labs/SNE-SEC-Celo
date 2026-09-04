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
GET  /v1/x402/reviews/{review_id}  (only when x402 is fully configured)
POST /v1/review-diffs
GET  /.well-known/agent.json
GET  /.well-known/sne-sec-capabilities.json
```

Every persisted Review is append-only at the database boundary. Rescanning creates another Review
and `ReviewDiff` classifies resolution, regression, unchanged results, and coverage changes.

## x402 review delivery on Celo

The optional paid delivery route uses x402 v2 `exact` with Celo mainnet USDC. Its offer is explicit:
`eip155:42220`, asset `0xcEBA9300f2b948710d2653dD7B07f33A8B32118C`, six decimals,
and an integer atomic amount. Dollar shorthand and implicit assets are not admitted.

The facilitator does not decide settlement truth. Before `/settle`, the service durably records a
payment intent without retaining the signature or raw authorization. After a successful
facilitator response, it records that response as a claim and independently queries Celo. The
buffered Review response is released only after all of the following agree:

```text
x402 requirement + EIP-3009 authorization
  -> durable payment intent
  -> facilitator settlement claim
  -> Celo chain ID 42220
  -> successful direct transferWithAuthorization call to USDC
  -> exact payer, payee, amount, validity window, and nonce identity
  -> one unambiguous ERC-20 Transfer log
  -> canonical receipt block with the configured latest-head confirmation count
  -> append-only settlement admission
  -> Review delivery
```

If the facilitator broadcasts successfully but the independent RPC is temporarily unavailable or
disagrees, delivery fails closed while the durable claim preserves the ambiguous effect. Retrying
the same authorization re-observes that transaction and, once admitted, resumes delivery without
asking the facilitator to broadcast it again.

`SNE_SEC_CELO_X402_ENABLED=true` fails startup unless the dedicated identity wallet is configured
as `SNE_SEC_CELO_AGENT_WALLET`, the receive-only destination is configured as
`SNE_SEC_CELO_X402_PAY_TO`, and the Celo facilitator credential is injected at runtime as
`SNE_SEC_CELO_X402_API_KEY`. The payment destination may be an operator treasury and does not
grant the service signing authority. The credential is only attached to `/settle`; it is never
written to the database or returned by the API. Optional controls are
`SNE_SEC_CELO_X402_AMOUNT_ATOMIC`, `SNE_SEC_CELO_X402_MIN_CONFIRMATIONS`,
`SNE_SEC_CELO_X402_FACILITATOR_URL`, and `SNE_SEC_CELO_RPC_URL`.

The current verifier deliberately admits the direct EIP-3009 path only. Alternate transfer paths
and ambiguous events fail closed until they receive their own versioned admission policy. The V1
micropayment policy defaults to one canonical Celo confirmation; it is explicit and configurable,
and it does not mislabel L2 inclusion as Ethereum L1 finality.

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

For hosted operation, the preferred Askbot-style flow creates a Windows-user-bound DPAPI vault,
enrolls a facilitator credential with a gasless message, publishes the existing treasury as the
x402 `payTo`, and enables Railway only after every prerequisite is present:

```powershell
& .\.venv\Scripts\sne-sec-celo-provision.exe `
  --pay-to <CELO_TREASURY_ADDRESS> `
  --railway `
  --enable
```

See [operational provisioning](docs/operations/provisioning.md). The production identity is
registered on Celo Mainnet as ERC-8004 agent `9814`; the mint remains a separate, one-shot
on-chain effect from ordinary hosted provisioning.

## Hosted agent URI

The public reference agent is deployed from this repository at:

```text
https://sne-sec-celo-agent-production.up.railway.app/.well-known/agent.json
```

The Railway service uses the repository Dockerfile, the checked-in `.railway/railway.ts`
infrastructure definition, a persistent `/data` volume for append-only reference Reviews, and
`/healthz` as its deployment gate. The IaC binds the application, service domain, and Railway
healthcheck to port 8000. A minimal root entrypoint admits ownership of the mounted volume and
immediately replaces itself with the application running as the unprivileged `sne-sec` user.
Uvicorn admits Railway's forwarded scheme so x402 resource URLs retain public HTTPS. Wallet
private material is never present in the service.

## Verify

```powershell
& .\scripts\verify.ps1
python scripts\witness_reference_path.py https://celo.org
python scripts\witness_celo_readiness.py
npm ci
npm run check
docker build -t sne-sec-celo .
```

See [the public/private boundary](docs/architecture/public-private-boundary.md) and
[the constitution](CONSTITUTION.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
