// SPDX-License-Identifier: MIT
/** Wire protocol for src/vault.worker.ts and public vault records (never secrets). */
import type { Hex } from 'viem';
import type { ChainId } from './ops';

export interface WireScope {
  chainId: ChainId;
  factory: `0x${string}`;
  namespace: string;
  accountIndex: string;
  epoch: string;
}

export interface VaultPublicKey { root: Hex; recRoot: Hex; pkSeed: Hex }
export interface WireLayerSig { wots: Uint8Array[]; auth: Uint8Array[] }

export type VaultWorkerRequest =
  | { id: number; type: 'generate' }
  | { id: number; type: 'import'; seedHex: string }
  | { id: number; type: 'fresh-seed' }
  | { id: number; type: 'keygen'; scope: WireScope; keepCurrent?: boolean }
  | { id: number; type: 'stage-recovery'; scope: WireScope; expectedRoot: Hex; seedHex: Hex }
  | { id: number; type: 'activate' }
  | { id: number; type: 'sign'; expectedRoot: Hex; idx: number; digestHex: Hex; needsTop: boolean }
  | { id: number; type: 'recover-sign'; expectedRoot: Hex; recNonce: string; digestHex: Hex }
  | { id: number; type: 'lock' };

/** Distributive omit so each union member keeps its own fields. */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
export type VaultWorkerMessage = DistributiveOmit<VaultWorkerRequest, 'id'>;

export type VaultWorkerResponse =
  | { id: number; type: 'progress'; label: string }
  | { id: number; type: 'seed'; seedHex: string }
  | { id: number; type: 'imported' }
  | { id: number; type: 'keygen'; publicKey: VaultPublicKey; keygenMs: number }
  | { id: number; type: 'signed'; l0: WireLayerSig; l1: WireLayerSig | null; bytes: number; signMs: number }
  | { id: number; type: 'recover-signed'; wots: Uint8Array[]; auth: Uint8Array[]; signMs: number }
  | { id: number; type: 'activated' }
  | { id: number; type: 'locked' }
  | { id: number; type: 'error'; message: string };

/** Public record stored in localStorage — no secrets. */
export interface VaultRecord {
  chainId: ChainId;
  factory: `0x${string}`;
  vault: `0x${string}`;
  namespace: string;
  accountIndex: string;
  createdAt: string;
  epochs: Record<string, VaultPublicKey>;
  currentEpoch: string;
  txs: { label: string; hash: `0x${string}`; status?: 'pending' | 'success' | 'reverted' }[];
  pendingDeployment?: Hex;
  pendingRecovery?: RecoveryIntent;
}

/** Public, immutable recovery intent. Never contains a backup seed. */
export interface RecoveryIntent {
  oldEpoch: string;
  oldRoot: Hex;
  recNonce: string;
  newEpoch: string;
  newPublicKey: VaultPublicKey;
  digest: Hex;
  replacesSeed: boolean;
  calldata?: Hex;
  hash?: Hex;
  submissionUncertain?: boolean;
}
