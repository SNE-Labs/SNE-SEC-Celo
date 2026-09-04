# Operational provisioning

The hosted agent follows the same local-custody pattern as SNE Labs Askbot while retaining a
sovereign implementation. A dedicated agent identity signs facilitator enrollment and future
ERC-8004 registration. The existing operator treasury is the x402 payment destination. These are
different authorities.

```text
Windows DPAPI vault                         Railway runtime
--------------------                       ---------------
agent signing key        NEVER UPLOADED
facilitator credential  -----------------> secret environment variable
agent public address    -----------------> public identity variable
treasury public address -----------------> x402 payTo variable
```

The default vault is
`%LOCALAPPDATA%\SNE-Labs\SNE-SEC-Celo\operational-secrets.dpapi`. It is encrypted for the current
Windows user. Back it up separately from the repository; copying it does not make it decryptable by
another Windows account.

Provisioning is idempotent and save-before-effect. It persists the wallet before requesting a
facilitator credential. If the POST result cannot be observed, the vault records `AMBIGUOUS` and
refuses to repeat issuance automatically. Reconcile that condition through `x402.celo.org`.

Run from the repository with the already admitted treasury address:

```powershell
& .\.venv\Scripts\python.exe -m pip install -e ".[wallet-tools]"
& .\.venv\Scripts\sne-sec-celo-provision.exe `
  --pay-to <CELO_TREASURY_ADDRESS> `
  --railway `
  --enable
```

The three identity variables are published with deploys suppressed. `SNE_SEC_CELO_X402_ENABLED`
is changed last, so an incomplete publication leaves the paid route disabled. The safe command
summary contains only public addresses, a credential prefix, and the vault path.

This command does not perform an ERC-8004 transaction. Registry minting remains a separate,
explicit on-chain effect requiring gas and its own witness.

After independently funding the dedicated identity with an admitted Celo fee currency, persist and
broadcast the one-shot mint intent. The command signs inside the DPAPI boundary, persists only the
transaction hash, and never retries a broadcast whose result is ambiguous:

```powershell
& .\.venv\Scripts\sne-sec-celo-register.exe mint `
  --agent-uri https://sne-sec-celo-agent-production.up.railway.app/.well-known/agent.json

& .\.venv\Scripts\sne-sec-celo-register.exe reconcile
```

Only a canonical receipt with one matching ERC-721 `Transfer`, one matching `Registered` event,
the exact owner and URI, and a fee below the durable cap can produce `RECONCILED`.
