# SNE-SEC Celo Agent repository contract

This repository is the sovereign open-source agent, payment, settlement, and
evidence protocol for evidence-backed security assessments. It must remain
executable without any source-code or runtime dependency on a private SNE Labs
repository.

## Binding boundaries

- The Apache-2.0 reference provider is real, deterministic, and independently executable.
- The proprietary SNE Labs assessment provider is an optional remote implementation of a
  public provider contract; it is never imported as code.
- Every semantic extraction records its source repository, exact commit, disposition, and
  destination in `provenance/REUSE_LEDGER.yaml`.
- A completed Review is immutable. A rescan creates a distinct Review.
- Every Finding references admitted Evidence from the same Review.
- Collectors never assign severity. Only versioned RuleEvaluations create Findings.
- `UNKNOWN`, `INCONCLUSIVE`, `ERROR`, and `NOT_APPLICABLE` never mean `PASS`.
- Payment and assessment state machines are orthogonal.
- Facilitator responses and buyer-supplied transaction data are claims, not settlement evidence.
- Settlement requires independently admitted Celo observations bound to the exact chain, asset,
  payer, payee, amount, authorization, and finality policy.
- Monetary values use integer atomic units with explicit asset identity and decimals.
- Payment authorizations, signing keys, tokens, and credentials never enter logs, evidence,
  reports, fixtures, examples, or committed source.
- Target admission, every DNS answer, redirects, and connected peers fail closed.
- The reference provider performs low-impact public-origin observation only. It never performs
  brute force, credential attacks, injection, exploitation, port scans, or enumeration.

## Required gates

For every change:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
python -m ruff check .
python -m mypy src
git diff --check
```

Protocol, payment, chain, API, persistence, and deployment changes additionally require their
integration tests and an explicit witness appropriate to the external effect.
