// SPDX-License-Identifier: MIT
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes } from '@noble/hashes/utils';
import type { CchsKey } from './cchs';

export interface AccountKeyScope {
  chainId: 56 | 97;
  factory: `0x${string}`;
  deploymentNamespace: string;
  accountIndex: bigint;
  epoch: bigint;
}

const enc = new TextEncoder();
export const ACCOUNT_KEY_DOMAIN = 'bsc-quantum-vault/account/v1';

function u64(n: bigint): Uint8Array {
  if (typeof n !== 'bigint' || n < 0n || n > 0xffffffffffffffffn) throw new Error('account index and epoch must be unsigned 64-bit integers');
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n);
  return out;
}

export function validateScope(scope: AccountKeyScope): void {
  if (scope.chainId !== 56 && scope.chainId !== 97) throw new Error('only BSC mainnet (56) and testnet (97) are supported');
  if (!/^0x[0-9a-fA-F]{40}$/.test(scope.factory)) throw new Error('factory must be a 20-byte hex address');
  if (!scope.deploymentNamespace || scope.deploymentNamespace.length > 256 || scope.deploymentNamespace.trim() !== scope.deploymentNamespace) throw new Error('deployment namespace must be a nonempty, trimmed string of at most 256 characters');
  u64(scope.accountIndex); u64(scope.epoch);
}

/** Canonical scope for journals and UI; addresses are case insensitive. */
export function accountScopeId(scope: AccountKeyScope): string {
  validateScope(scope);
  return JSON.stringify([ACCOUNT_KEY_DOMAIN, scope.chainId, scope.factory.toLowerCase(), scope.deploymentNamespace, scope.accountIndex.toString(), scope.epoch.toString()]);
}

/**
 * Derive distinct spending and recovery secrets. The deployment namespace must
 * be a stable unique identifier for this application's actual deployment; do
 * not reuse the upstream project's key tree even when importing the same seed.
 * The browser lab supplies a fresh random 32-byte seed, never a funded wallet.
 */
export function deriveAccountKey(seed: Uint8Array, scope: AccountKeyScope): CchsKey {
  validateScope(scope);
  if (!(seed instanceof Uint8Array) || (seed.length !== 32 && seed.length !== 64)) throw new Error('seed must contain 32 or 64 bytes');
  const factory = Uint8Array.from(scope.factory.slice(2).match(/../g)!, h => Number.parseInt(h, 16));
  const namespace = enc.encode(scope.deploymentNamespace);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, namespace.length);
  const context = concatBytes(enc.encode(ACCOUNT_KEY_DOMAIN), Uint8Array.of(0), u64(BigInt(scope.chainId)), factory, length, namespace, u64(scope.accountIndex), u64(scope.epoch));
  return {
    master: hkdf(sha256, seed, undefined, concatBytes(context, Uint8Array.of(0), enc.encode('spend')), 32),
    recoveryMaster: hkdf(sha256, seed, undefined, concatBytes(context, Uint8Array.of(0), enc.encode('recovery')), 32),
  };
}
