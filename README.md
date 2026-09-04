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

See [the public/private boundary](docs/architecture/public-private-boundary.md) and
[the constitution](CONSTITUTION.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
