# Public/private product boundary

Status: Accepted
Workpack: `SEC-HACK-PUBLIC-000`

## Decision

SNE-SEC Celo Agent is the open source agent, payment, settlement and evidence protocol for evidence-backed security assessments. SNE Labs operates a separate proprietary assessment provider, while this repository includes an executable reference provider.

The repository is independently cloneable and executable. Its reference provider performs a real,
bounded assessment and produces admitted observations, evidence, rule evaluations, findings, an
immutable Review, and ReviewDiff. The hosted provider extends coverage through the same public
contract; it does not define the protocol's truth.

## Ownership

| Concern | Public agent | Proprietary provider |
| --- | --- | --- |
| ERC-8004 identity and agent manifest | Owns | No |
| x402 challenge and authorization handling | Owns | No |
| Celo observation and settlement admission | Owns | No |
| Entitlement state | Owns | No |
| Provider contract and evidence envelope | Owns | Implements |
| Reference collectors and ruleset | Owns | No |
| Complete production collectors and rulesets | No | Owns |
| Production scoring and commercial intelligence | No | Owns |
| Review and ReviewDiff public semantics | Owns | Implements |
| Pix and internal production operations | No | Owns |

## Trust boundary

```text
durable AssessmentIntent
        ↓
authenticated provider request
        ↓
AssessmentProvider
        ↓
signed EvidenceBundle claim
        ↓
schema + subject + digest + signer admission
        ↓
immutable Review
```

A hosted provider response is not trusted merely because it arrived over authenticated transport.
The public agent verifies the response envelope and admits only the provider identity and
capabilities configured for that Review. Raw credentials and payment authorizations never cross
the assessment-provider boundary.

## Reproducibility criterion

A clean clone must be able to install dependencies, run the complete test suite, start the public
API, assess an admitted public origin with the reference provider, retrieve the completed Review,
perform a second Review, and calculate ReviewDiff without access to private SNE Labs code or
credentials.
