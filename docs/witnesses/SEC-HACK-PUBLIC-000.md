# SEC-HACK-PUBLIC-000 witness

Date: 2026-09-04
Status: gates 1–5 complete; gates 6–8 deliberately require separately controlled external effects

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

- 14 unit/API/domain tests: PASS;
- Ruff: PASS;
- strict mypy over 15 source files: PASS;
- `git diff --check`: PASS;
- live reference witness against `https://celo.org`: PASS;
- witness facts: 6 Observations, 6 Evidence records, 5 RuleEvaluations, 3 Findings, score 89,
  persisted digest reproduced.

The witness records bounded metadata only. It does not claim a full production assessment of
`celo.org`.

## External-effect boundary

No wallet, ERC-8004 identity, facilitator authorization, or Celo mainnet transaction was created by
this gate. Those actions require a dedicated operational wallet, external registration, and
attribution admission. Mainnet activity remains forbidden until those controls are complete.
