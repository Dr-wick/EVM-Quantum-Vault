# Using a vault

A vault is a separate contract address that holds assets. Your ordinary wallet connects to the application and pays transaction fees. A separate vault backup supplies the key used to authorize outgoing operations.

This release is experimental and unaudited. Begin with the [local browser harness](development.md#local-browser-harness) or your own testnet deployment. No factory address is configured in the public source by default.

## Before starting

You need a compatible injected wallet, BNB for the selected network's transaction fees, a configured factory, and an offline location for the vault backup. The browser must support IndexedDB.

Keep two things safe: **the secret backup and the browser's signing history**. The backup can restore keys and vault metadata, but cannot reconstruct every signature previously produced. Avoid clearing browser data or using the same seed in multiple profiles or devices.

## 1. Create a vault

Connect your ordinary wallet and select the configured BSC network. Generate a fresh vault seed in the application, save the backup offline, and complete its confirmation step. The application derives the public key locally and cross-checks the predicted vault address with the factory before requesting the deployment transaction.

Confirm the transaction in your ordinary wallet and wait for the result. Save the complete backup containing the vault address, factory, network, namespace, account index, epoch, and public-key fields. The factory deployer and website operator have no administrator reset key.

Do not enter your ordinary wallet's recovery phrase or private key. The vault uses its own seed.

## 2. Deposit

Use the BNB deposit form and confirm the transfer in your connected wallet. You can also transfer supported assets directly to the vault address on the same network.

The interface displays and manages native BNB directly. BEP-20 token transfers out of the vault require an advanced contract call. Do not send assets from another chain or NFTs the interface cannot manage.

## 3. Send assets

Import or unlock the vault backup, enter the destination and amount, and review the operation. After confirmation, the application reserves a one-time signing index, creates the vault signature locally, and asks your ordinary wallet to submit the call and pay gas.

Canceling the wallet prompt does not restore that signing index. Once reserved, it is never reused. For advanced calls, verify the target contract and exact call data as well as any native value sent.

If a transaction has a hash but confirmation times out, check the wallet and refresh chain status. Do not assume the transaction was never sent or manually replay its calldata.

## 4. Rotate to a new backup

With the current backup loaded, generate a fresh recovery backup. The replacement seed is independent of the old one. Save and confirm the replacement file before submitting the recovery operation.

Continue the same pending recovery intent if the wallet prompt is rejected. If submission is uncertain, reconcile its transaction hash and chain state rather than generating a different replacement key. The application can associate a supplied transaction hash only after checking its target and full recovery calldata.

Once the new public key and epoch are confirmed on-chain, import the replacement backup to continue. The vault address and its assets remain in place, while the old key no longer authorizes operations.

Recovery cannot safely infer an unknown history of recovery signatures from another device or a rolled-back database. Retain the original browser and records if that history is uncertain.

## Common questions

**Does depositing encrypt my balance?** No. Balances and transfers remain visible on-chain. Hash-based signatures control authorization to move funds.

**Can the connected wallet alone withdraw?** No. Submitting a transaction and paying gas is separate from providing the vault's valid signature.

**Can the operator reset a lost backup?** No. There is no administrator, email reset, or customer-support override in these contracts.

**Can I import a backup on a new computer and immediately spend?** Not safely without reliable signing history. The application does not rebuild a missing spending journal from chain counters. Review [the recovery limits](../SECURITY.md#recovery-and-backups) before changing devices.

**Does locking or closing the page move my funds?** No. The funds remain at the vault address. Locking terminates the signing worker and clears application-held references; it does not delete downloaded backups or guarantee secure erasure from the device.

**Can I use the project on another EVM network?** This version restricts contract creation and client configuration to BSC mainnet and testnet. The repository name does not imply deployment support elsewhere.
