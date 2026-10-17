# Architecture

EVM-Quantum-Vault separates an asset-holding contract from the wallet that submits transactions. The vault accepts a call only after verifying a signature under its stored hash-tree public key. A connected wallet pays gas and transports the authorization to the chain.

## Components

| Component | Responsibility |
| --- | --- |
| `BscQuantumVaultFactory` | Predict and create vaults with CREATE2; forward any supplied BNB to the vault |
| `BscQuantumVaultBase` | Execution digests, leaf-index lanes, subtree cache, recovery, and external calls |
| `BscQuantumVault` | Keccak verifier implementation and vault initialization |
| `src/crypto/cchs.ts` | Reference CCHS-K-20 key generation, signing, verification, and digests |
| `src/crypto/fast.ts` | WASM-backed hashing for browser and CLI computation |
| `src/crypto/derive.ts` | Account-scoped derivation of spending and recovery secrets |
| `src/crypto/journal.ts` | Durable spending-index reservations and recovery-digest bindings |
| `src/vault/client.ts` | Browser operation sequencing, chain reconciliation, and wallet submission |
| `src/vault.worker.ts` | Key generation and signing away from the UI thread |

The factory is permissionless and has no administrator, protocol fee, upgrade entry point, or operation that pulls tokens from users. Its salt binds the spending root, recovery root, and public seed. Supplied BNB is forwarded to the predicted vault. Vault ownership is established by the signature keys, not by the caller of `deploy`.

Both factory and vault initialization reject chain IDs other than 56 and 97. Additional networks require deliberate protocol, configuration, and test changes.

## Signature structure

The implementation uses CCHS-K-20, a stateful Keccak-based construction adapted from Aegis:

| Parameter | Value |
| --- | --- |
| Winternitz parameter | 16 |
| Signature chains | 67: 64 message digits and 3 checksum digits |
| Spending tree | Two layers, each height 10 |
| Spending leaves | 1,048,576 per key epoch |
| Lanes | 16 partitions of 65,536 leaves; the browser currently uses lane 0 |
| Recovery tree height | 8 |
| Public tree seed | 16 bytes |

`executeFirst` authenticates the operation at a bottom-tree leaf, then authenticates that subtree root against the top tree. The vault caches the bottom root. `execute` can subsequently verify a bottom-layer proof against that cache.

A first-use signature contains 4,928 bytes of WOTS values and authentication paths; a cached-subtree signature contains 2,464 bytes. These are signature payload sizes, not total transaction calldata or gas estimates. Caching is keyed by epoch, so an old cached root is not reused after recovery.

This is not a standardized SLH-DSA implementation or a certification claim. The code and tests are provided for review and experimentation.

## Keys and compatibility

A vault seed is expanded with HKDF-SHA-256 into distinct spending and recovery secrets. The derivation context contains:

1. The fixed domain `bsc-quantum-vault/account/v1`.
2. Chain ID and factory address.
3. A stable deployment namespace.
4. Account index and epoch.
5. A separate `spend` or `recovery` label.

The factory, namespace, account index, and epoch are essential backup metadata. They are not interchangeable with a project name or website URL. The browser namespace is `bqv-web/v1`; CLI demonstrations use their own namespace.

The public project name is EVM-Quantum-Vault, while the Solidity names, KDF domains, digest labels, journal identifiers, and `bqv-seed-backup-v1` format remain unchanged. Renaming these constants would change derived keys or prevent existing records from being read. A brand change performs no on-chain migration.

## Authorizing an outgoing call

1. Read the current vault key, epoch, lane state, and cache status.
2. Calculate the execution digest locally and compare it with the contract's `digestAt` result.
3. Permanently reserve a signing index in an IndexedDB transaction. If another tab obtained the candidate index first, calculate and cross-check the digest for the new reservation.
4. Ask the worker to sign, then encode `executeFirst` or `execute`.
5. Ask the connected wallet to submit the transaction.
6. Record the transaction hash and reconcile the receipt. A timeout is not treated as proof of failure and does not trigger automatic resubmission.

The execution digest binds `BQV_EXECUTE_V1`, chain ID, vault address, lane nonce, leaf index, target, value, and the Keccak hash of call data. An accepted call advances that lane's nonce and index before the external call. If the external call reverts, the contract transaction reverts, but the local signing reservation still remains consumed.

The contract rejects an already-consumed index. It also permits forward skips so the client can abandon a leaf whose signature was produced but never accepted on-chain. A chain counter alone cannot account for such unpublished signatures.

## Persistent state

Public vault metadata, public key epochs, transaction hashes, and pending recovery intent are stored in localStorage. Secret seeds are held temporarily in application/worker memory and saved only in the backup file explicitly downloaded by the user.

The signing journal uses IndexedDB read/write transactions and returns a reservation only after transaction completion. It has no localStorage or memory fallback. A backup import does not reconstruct missing journal entries.

This protects concurrent use in the same browser database, not full database rollback, cloned profiles, malicious extensions, or independent signing on another device. See [SECURITY.md](../SECURITY.md) before integrating the signer.

## Key recovery

Recovery is a public-key rotation at the same vault address. It does not transfer assets to a new account.

The browser generates an independent replacement seed, derives a new spending root, recovery root, and public seed, and requires the new backup to be saved and confirmed. It records a fixed recovery intent and binds its digest to the current recovery leaf before signing. The `BQV_RECOVER_V1` digest binds the vault, chain, recovery nonce, and complete replacement public key.

After successful verification, `recover` replaces the three public-key fields and increments the epoch and recovery nonce. New epoch storage starts fresh spending lanes and cache entries. The client confirms all three fields and the epoch before retiring the old key and asking for the replacement backup.

The recovery nonce is not reset by rotation; this implementation allows at most 256 successful recoveries per vault. A persisted recovery leaf must not authorize two replacement keys. Unknown cross-device recovery-signature history is an unresolved safety boundary.

## Asset and network boundaries

The vault can receive native BNB and hold BEP-20 balances. An authorized call can invoke a token's `transfer` function or another contract. The UI provides BNB-oriented forms and an advanced contract-call path; it does not guarantee compatibility with every token or NFT.

RPC providers receive network requests and queried addresses. On-chain amounts and calls remain public. There is no server-side seed custody, protocol token, or built-in yield mechanism.
