// SPDX-License-Identifier: MIT
import { bytesToHex } from 'viem';
import { cchsK, toHex, type Cchs } from '../crypto/cchs';
import { deriveAccountKey } from '../crypto/derive';
import { parseSeedBackup, recoveryDigestFor, scopeFor } from './ops';
import type { VaultKeyState } from './chain';
import type { RecoveryIntent, VaultPublicKey, VaultRecord } from './types';

export function samePublicKey(a: VaultPublicKey, b: VaultPublicKey): boolean {
  return a.root.toLowerCase() === b.root.toLowerCase() && a.recRoot.toLowerCase() === b.recRoot.toLowerCase()
    && a.pkSeed.toLowerCase() === b.pkSeed.toLowerCase();
}

export function assertCurrentKey(record: VaultRecord, state: VaultKeyState): VaultPublicKey {
  const pk = record.epochs[record.currentEpoch];
  if (!pk || record.currentEpoch !== String(state.epoch) || !samePublicKey(pk, state)) {
    throw new Error('The on-chain key has changed. This record cannot sign; refresh and import the current backup.');
  }
  return pk;
}

export function recoveryDigest(record: VaultRecord, intent: RecoveryIntent) {
  return bytesToHex(recoveryDigestFor(cchsK, { chainId: record.chainId, vault: record.vault,
    recNonce: BigInt(intent.recNonce), newRoot: intent.newPublicKey.root,
    newRecRoot: intent.newPublicKey.recRoot, newPkSeed: intent.newPublicKey.pkSeed }));
}

export function assertRecoveryIntent(record: VaultRecord, intent: RecoveryIntent): void {
  if (BigInt(intent.newEpoch) !== BigInt(intent.oldEpoch) + 1n || BigInt(intent.recNonce) >= 256n
    || BigInt(intent.recNonce) < 0n || !intent.replacesSeed
    || intent.oldRoot !== record.epochs[intent.oldEpoch]?.root
    || intent.digest !== recoveryDigest(record, intent)) throw new Error('The recovery record is corrupt. Signing stopped; preserve the original backup and recovery record.');
}

export function recoveryState(record: VaultRecord, state: VaultKeyState): 'waiting' | 'confirmed' {
  const intent = record.pendingRecovery;
  if (!intent) throw new Error('No pending recovery record');
  assertRecoveryIntent(record, intent);
  if (String(state.epoch) === intent.newEpoch && state.recNonce === BigInt(intent.recNonce) + 1n
    && samePublicKey(state, intent.newPublicKey)) return 'confirmed';
  if (String(state.epoch) === intent.oldEpoch && state.root.toLowerCase() === intent.oldRoot.toLowerCase()
    && String(state.recNonce) === intent.recNonce) return 'waiting';
  throw new Error('The on-chain key does not match this recovery. Do not sign or submit again; import the active backup.');
}

export function verifyRecoveryBackup(text: string, record: VaultRecord, intent: RecoveryIntent, engine: Cchs): void {
  const { seed, publicFields: p } = parseSeedBackup(text);
  try {
    if (!p || p.chainId !== record.chainId || p.vault?.toLowerCase() !== record.vault.toLowerCase()
      || p.factory?.toLowerCase() !== record.factory.toLowerCase() || p.namespace !== record.namespace
      || p.accountIndex !== record.accountIndex || p.epoch !== intent.newEpoch) throw new Error('New recovery backup metadata does not match');
    const key = deriveAccountKey(seed, scopeFor(record.chainId, record.factory, BigInt(p.epoch), p.namespace, BigInt(p.accountIndex)));
    const pub = engine.keygen(key);
    key.master.fill(0); key.recoveryMaster?.fill(0);
    const actual = { root: toHex(pub.root), recRoot: toHex(pub.recRoot), pkSeed: toHex(pub.seed) };
    if (!samePublicKey(actual, intent.newPublicKey) || !samePublicKey(actual, p as VaultPublicKey)) throw new Error('New recovery backup seed does not match');
  } finally { seed.fill(0); }
}
