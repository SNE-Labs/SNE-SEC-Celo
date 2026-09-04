# SNE-SEC Celo Agent Constitution

Version: `sne-sec-celo-agent-v1`

This document is normative. Each clause requires an executable invariant or an explicitly
recorded external control before the related capability is accepted.

## Product identity

1. This repository is an executable product surface, not a sample client for private software.
2. Open protocol and reference implementation do not imply publication of proprietary assessment
   implementations.
3. Provider capabilities and coverage are explicit, versioned, and never inferred from branding.

## Technical truth

1. Observation is not Finding; Finding is not exploitation; Review is not pentest.
2. A collector emits facts without severity.
3. Every Finding is caused by one versioned failed RuleEvaluation and references same-Review
   admitted Evidence.
4. Missing, unsupported, timed-out, malformed, and untested facts never become PASS.
5. A completed Review is immutable. A rescan creates a new Review.
6. ReviewDiff distinguishes improvement, regression, unchanged risk, and coverage change.
7. Canonical objects reject floating-point values and produce reproducible SHA-256 digests.

## Provider boundary

1. The reference provider runs locally and performs a genuine evidence-backed assessment.
2. A hosted provider is selected through the same public contract and no private package import.
3. Hosted evidence bundles are admitted only after schema, Review, target, provider identity,
   digest, and signature verification.
4. Provider assertions cannot create settlement evidence or entitlement.

## Economic truth

1. Orders, payment attempts, settlement claims, chain observations, settlements, entitlements,
   and Reviews are separate state machines.
2. An x402 facilitator response is a claim about settlement.
3. Only independent Celo observation can admit a final settlement.
4. Settlement identity binds the exact chain, asset contract, payer, payee, atomic amount, and
   authorization identity under an explicit finality policy.
5. One chain effect cannot settle more than one economic intent.
6. Settlement and entitlement commit atomically or remain safely retryable.

## Safety

1. Targets are limited to admitted public HTTP(S) origins.
2. Host syntax, DNS answers, selected destination, redirect targets, and connected peer addresses
   are validated independently and fail closed.
3. Requests, redirects, response bytes, concurrency, and runtime are bounded.
4. The reference provider is read-only and low impact; exploitation is outside its authority.
5. Signing authority and assessment authority remain separate.
6. Secrets and reusable payment authorizations never enter durable public artifacts.
