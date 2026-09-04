# SEC-HACK-PUBLIC-000 witness

Date: 2026-09-04
Status: gates 1–5 and hosted Railway witness complete; gates 6–8 deliberately require separately controlled external effects

## Public boundary

The accepted boundary is recorded in commit `a02e905` and in
`docs/architecture/public-private-boundary.md`. The public repository is licensed under
Apache-2.0 and the proprietary assessment engine remains a separate provider implementation.

## Secret and history audit

The private source repository was audited before extraction with Gitleaks 8.30.1:

- complete Git history: zero detections;
- tracked product tree: zero detections;
- ignored `output/`, `tmp/`, documentation, examples, and generated frontend output: zero
  detections;
- installed `.venv` dependencies were excluded from product findings after the raw scan identified
  only upstream cryptography test vectors and generic package strings;
- no `.venv` or generated dependency directory is copied or committed here.

The public repository is scanned again before each publication gate. Findings are handled outside
public logs so a detector cannot itself disclose a credential.

## Executable reference path

The reference provider proves:

```text
target normalization
→ DNS answer admission
→ connection pinned to an admitted public address
→ connected-peer validation
→ bounded HTTP observation
→ Evidence admission
→ versioned RuleEvaluation
→ Finding
→ immutable SQLite Review
→ retrieval with digest reproduction
→ rescan / ReviewDiff
```

Local gates on 2026-09-04:

- 14 unit/API/domain tests on reference commit `4c52436`: PASS;
- Ruff: PASS;
- strict mypy over 15 source files: PASS;
- `git diff --check`: PASS;
- live reference witness against `https://celo.org`: PASS;
- clean clone of public commit `4c52436cf1deb68acd9c0f282ad5a9cc6f7e92f6`: install, tests,
  lint, strict typing, and live witness PASS with no private repository access;
- GitHub Actions run `33845797772`: Python proof and Linux container build PASS;
- witness facts: 6 Observations, 6 Evidence records, 5 RuleEvaluations, 3 Findings, score 89,
  persisted digest reproduced.

The witness records bounded metadata only. It does not claim a full production assessment of
`celo.org`.

## External-effect boundary

No wallet, ERC-8004 identity, facilitator authorization, or Celo mainnet transaction was created by
this gate. Those actions require a dedicated operational wallet, external registration, and
attribution admission. Mainnet activity remains forbidden until those controls are complete.

## Hosted Railway witness

The production deployment correction was witnessed on 2026-09-04:

- commit `f839494` introduced a minimal root entrypoint that admits ownership of the dedicated
  `/data` volume and immediately replaces itself with the application as `sne-sec`;
- GitHub Actions run `33896134603` passed the Python proof, typed Railway IaC, Linux image build,
  and a container witness seeded with a root-owned SQLite file;
- the local container witness observed a healthy API, effective PID 1 UID `999`, and
  `reviews.sqlite3` owned by `sne-sec:sne-sec`;
- the deprecated `railway.json` configuration was replaced by `.railway/railway.ts` without
  deleting or replacing the existing source, domain, variable, or volume;
- Railway deployment `6ca5cce9-8c4b-4046-9e17-d3213f9d62a9` passed `/healthz` after the declared
  `PORT=8000` was bound to the existing target port;
- public Review `review_ac8c7054897c4ec9ada5feae8dfcf8f3` completed against
  `https://celo.org` with 6 Observations, 6 Evidence records, 5 RuleEvaluations, 3 Findings, and
  score 89;
- its result digest
  `sha256:ab13ab447559a501f93509009e5486ba144208bacbd945d2d736c7d72b54c16e` was reproduced before
  and after an explicit service restart, proving durable retrieval from the mounted volume.

The failed predecessors were not counted as successful deployments: the first could not open
SQLite on the mounted volume, and the second started the application but failed the Railway
healthcheck because its target port was not declared as `PORT`.

## x402 settlement-admission implementation

The next gate was implemented locally without creating a wallet, authorization, facilitator
settlement, or mainnet transaction:

- x402 Python SDK `2.22.0` is pinned and its inspected upstream commit is recorded in the reuse
  ledger;
- the paid Review route is absent unless x402 is explicitly enabled with a dedicated public
  `payTo` address and a runtime-only facilitator credential;
- a before-settle hook writes the exact payment intent before the facilitator may cause an
  external effect;
- a successful facilitator response is persisted as a claim, never accepted as settlement;
- an independent Celo RPC verifier binds chain `42220`, the direct EIP-3009 calldata and nonce,
  exact USDC payer/payee/amount, one Transfer log, canonical block hash, and the configured
  latest-head confirmation policy;
- the Review body remains buffered and is replaced by a 402 failure if independent admission
  cannot complete;
- a retry can recover a durable ambiguous facilitator claim through independent observation and
  skip a second settlement call;
- append-only SQLite uniqueness rejects authorization, transaction, event, observation, and
  settlement replay.

The deterministic integration witness exercised `402 -> signed retry -> facilitator claim ->
independent Celo observation -> delivery` and the negative case where a successful facilitator
  claim was followed by an RPC chain mismatch. The first delivered the immutable Review; the second
  returned 402 and created no settlement, then recovered on retry without a second facilitator
  settlement call once the independent source agreed. A read-only live probe observed Celo RPC chain ID
`0xa4ec`, a non-null `finalized` block, and Celo facilitator support for x402 v2 `exact` on
`eip155:42220`.

This is implementation evidence, not mainnet adoption evidence. Enabling the hosted route and
recording one real payment remain separately controlled external effects.

Local gate results for this implementation on 2026-09-04:

- 24 unit, domain, persistence, and API integration tests: PASS;
- Ruff and strict mypy over 21 source files: PASS;
- TypeScript Railway IaC check and `git diff --check`: PASS;
- Linux image build with x402 `2.22.0`: PASS;
- mounted-volume witness: health `ok`, PID 1 UID `999`, SQLite owner `sne-sec:sne-sec`;
- read-only Celo readiness witness: PASS.
