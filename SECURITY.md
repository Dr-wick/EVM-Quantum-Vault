# Security policy

EVM-Quantum-Vault is experimental software. No independent contract or cryptographic audit has been performed. Local tests establish specific implementation behavior, not suitability for custody of real assets.

## Scope of protection

The vault verifies hash-based authorization for outgoing calls and key rotation. The factory and accounts are restricted to BSC chain IDs 56 and 97. They have no administrator withdrawal function or upgrade mechanism.

Execution digests bind the chain, vault, lane nonce, signing index, target, value, and call data. Recovery digests bind the chain, vault, recovery nonce, and replacement public key. Key derivation separates factories, deployment namespaces, account indices, epochs, spending secrets, and recovery secrets.

This does not encrypt on-chain balances, transactions, or signatures. It does not protect BSC consensus, ordinary gas-paying wallets, compromised devices, token issuer privileges, RPC availability, or the behavior of called contracts. CCHS-K-20 is a custom composition of hash-based primitives; no standardized SLH-DSA certification is claimed.

## Stateful signatures

**A one-time signing key must never authorize two different messages**, including signatures that were canceled, dropped, reverted, or never broadcast. On-chain nonces cannot reveal unpublished signatures.

The browser commits an IndexedDB reservation before signing and never releases that index. Read/write transactions serialize reservations across connections to the same database. Missing or corrupt spending records disable signing; there is no memory or localStorage fallback and no reconstruction from an on-chain counter.

These protections have limits:

- A complete rollback of a valid database cannot be detected by that database itself.
- Different origins, browser profiles, and devices do not share the same journal. Do not use the same key concurrently across them.
- Importing a seed backup restores key material and public metadata, not the missing spending journal.
- `initializeFresh` is only for a genuinely new key. Never use it to repair an existing key's missing history.
- Known restores, cloned profiles, or uncertain signing history require stopping use of the affected signing key. A fresh seed is necessary for rotation, but unknown recovery-signature history must also be resolved.

The current browser uses lane 0. The contract's additional lanes do not by themselves provide a safe multi-device enrollment protocol.

## Recovery and backups

Spending and recovery secrets are separate derivation outputs from a vault seed. Recovery replaces the public key with one derived from an **independent random seed**. Changing only an epoch under a leaked seed does not remove that seed holder's knowledge of derived keys.

The interface requires a downloaded and confirmed replacement backup, persists a fixed recovery intent, and binds each recovery leaf to its digest before signing. Pending operations are reconciled against the epoch and all three public-key fields. Unknown submissions are not automatically resent. The binding only protects the same unrolled-back database; it cannot establish that a recovery leaf was never used on another device.

Backups are **unencrypted secret files**. Anyone who obtains one may be able to authorize vault operations. Keep them offline and do not attach them to issues, support requests, logs, or pull requests. Losing all usable key material cannot be remedied by an administrator or email reset.

Locking terminates the worker and clears application-held references. JavaScript strings, browser memory, the operating system, extensions, and downloaded files cannot be securely erased by this application.

## Deployment and testing

No deployed factory is configured by default. Configure and verify your own deployment before enabling live operations. Publishing new client code does not update existing contracts.

Deployment is a dry run by default. Broadcasting requires `--broadcast`; chain 56 additionally requires `--allow-mainnet`. Deployment secrets belong in process environment variables, never frontend `VITE_` variables. Local CLI demo secrets and recovery backups belong in ignored `.local` files. Its process lock intentionally requires investigation after an abnormal exit rather than automatic removal.

Test seeds, fixture addresses, and test signatures are public synthetic data and must never hold real assets. In-memory EVM tests and the browser harness do not replace public testnet validation, wallet compatibility testing, production gas measurements, or an audit.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Dr-wick/EVM-Quantum-Vault/security/advisories/new) if it is enabled. If that route is unavailable, open an issue requesting a private contact channel without disclosing exploit details. Include affected code, reproduction steps, and potential impact through the private channel. Never send private keys or backups, and do not exploit funded accounts to demonstrate a problem.
