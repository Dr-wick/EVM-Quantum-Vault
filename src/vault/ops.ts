// SPDX-License-Identifier: MIT
/**
 * Shared vault-operation helpers — single authoritative implementation used by
 * both the web app (src/vault/*) and the CLI demo console (scripts/demo.ts).
 * Pure logic only: no network, no storage, no key material handling beyond the
 * public seed-backup codec.
 */
import {
  concatHex, encodeAbiParameters, encodeFunctionData, getContractAddress, hexToBytes, isAddress, keccak256, toFunctionSelector,
  type Abi, type Address, type Hex,
} from 'viem';
import { eq, toAbiLayerSig, toHex, type Cchs, type CchsSignature, type LayerSig } from '../crypto/cchs';
import { accountScopeId, type AccountKeyScope } from '../crypto/derive';
import artifacts from '../generated/contracts.json';

export type ChainId = 56 | 97;

interface ArtifactBundle {
  format: string; compiler: string;
  factory: { abi: Abi; bytecode: Hex; runtimeHash: string; runtimeBytes: number };
  vault: { abi: Abi; bytecode: Hex; runtimeHash: string; runtimeBytes: number };
}
export const ARTIFACTS = artifacts as unknown as ArtifactBundle;
export const FACTORY_ABI = ARTIFACTS.factory.abi;
export const VAULT_ABI = ARTIFACTS.vault.abi;

function configuredFactory(value: unknown): Address | null {
  if (value === undefined || value === '') return null;
  if (typeof value !== 'string' || !isAddress(value)) throw new Error('Configured factory must be a valid EVM address');
  return value;
}

/** Explicit deployment configuration; this repository ships no live factory. */
export const FACTORY: Record<ChainId, Address | null> = {
  56: configuredFactory(import.meta.env?.VITE_BSC_MAINNET_FACTORY),
  97: configuredFactory(import.meta.env?.VITE_BSC_TESTNET_FACTORY),
};
export const WEB_NAMESPACE = 'bqv-web/v1';
export const LANE_SIZE = 65_536;

export function chainIdOf(value: number): ChainId {
  if (value !== 56 && value !== 97) throw new Error('only BSC mainnet (56) or testnet (97) is supported');
  return value;
}

export function scopeFor(chainId: ChainId, factory: Address, epoch: number | bigint, namespace = WEB_NAMESPACE, accountIndex = 0n): AccountKeyScope {
  return { chainId, factory, deploymentNamespace: namespace, accountIndex, epoch: BigInt(epoch) };
}

// ------------------------------------------------------------ seed backup codec

export const SEED_BYTES = 32;
const CHECKSUM_BYTES = 4;
const SEED_HEX_LENGTH = (SEED_BYTES + CHECKSUM_BYTES) * 2;

/** 32-byte seed ‖ 4-byte keccak checksum, hex — Copy-friendly, typo-detectable. */
export function encodeSeedWithChecksum(seed: Uint8Array): string {
  if (seed.length !== SEED_BYTES) throw new Error(`seed must be ${SEED_BYTES} bytes`);
  const sum = hexToBytes(keccak256(seed)).slice(0, CHECKSUM_BYTES);
  const out = new Uint8Array(SEED_BYTES + CHECKSUM_BYTES);
  out.set(seed); out.set(sum, SEED_BYTES);
  return `0x${Array.from(out, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

export function decodeSeedWithChecksum(text: string): Uint8Array {
  const clean = text.trim().toLowerCase().replace(/\s+/g, '');
  if (!new RegExp(`^0x[0-9a-f]{${SEED_HEX_LENGTH}}$`).test(clean)) {
    throw new Error(`Invalid seed format: expected 0x followed by ${SEED_HEX_LENGTH} hex characters (received ${clean.length - 2})`);
  }
  const bytes = hexToBytes(clean as Hex);
  const seed = bytes.slice(0, SEED_BYTES);
  const expect = hexToBytes(keccak256(seed)).slice(0, CHECKSUM_BYTES);
  if (!eq(bytes.slice(SEED_BYTES), expect)) throw new Error('Seed checksum mismatch: the contents were mistyped or damaged; check the backup file');
  return seed;
}

/** Public (non-secret) fields embedded in a backup so one file can rebuild the record. */
export interface SeedBackupPublic {
  chainId?: ChainId;
  namespace: string;
  accountIndex: string;
  epoch: string;
  root: string;
  recRoot: string;
  pkSeed: string;
  factory: string | null;
  vault: string | null;
}

export function validateBackupPublic(value: unknown): asserts value is SeedBackupPublic {
  const p = value as SeedBackupPublic | undefined;
  if (!p || !/^(0|[1-9][0-9]*)$/.test(p.epoch) || !/^(0|[1-9][0-9]*)$/.test(p.accountIndex)
    || !/^0x[0-9a-f]{64}$/i.test(p.root) || !/^0x[0-9a-f]{64}$/i.test(p.recRoot)
    || !/^0x[0-9a-f]{32}$/i.test(p.pkSeed) || (p.factory !== null && !/^0x[0-9a-f]{40}$/i.test(p.factory))
    || (p.vault !== null && !/^0x[0-9a-f]{40}$/i.test(p.vault))
    || (p.chainId !== undefined && p.chainId !== 56 && p.chainId !== 97)) throw new Error('Invalid public metadata in the backup file');
  // The same validation used by the KDF protects namespace and integer ranges.
  accountScopeId({ chainId: p.chainId ?? 56, factory: (p.factory ?? `0x${'00'.repeat(20)}`) as Address,
    deploymentNamespace: p.namespace, accountIndex: BigInt(p.accountIndex), epoch: BigInt(p.epoch) });
}

export interface SeedBackupFile {
  format: 'bqv-seed-backup-v1';
  seed: string;
  public?: SeedBackupPublic;
  createdAt: string;
  note: string;
}

export function seedBackupFile(seed: Uint8Array, publicFields?: SeedBackupPublic): SeedBackupFile {
  return {
    format: 'bqv-seed-backup-v1',
    seed: encodeSeedWithChecksum(seed),
    ...(publicFields ? { public: publicFields } : {}),
    createdAt: new Date().toISOString(),
    note: 'EVM Quantum Vault backup seed with public metadata. Anyone with this file can authorize vault transactions. Keep it offline and private; do not share it in chats or cloud notes.',
  };
}

/** Accepts a backup JSON (either field layout) or a raw hex seed string. */
export function parseSeedBackup(text: string): { seed: Uint8Array; publicFields?: SeedBackupPublic } {
  const trimmed = text.trim();
  if (trimmed.startsWith('{')) {
    let parsed: unknown;
    try { parsed = JSON.parse(trimmed); } catch { throw new Error('Backup file is not valid JSON'); }
    const file = parsed as Partial<SeedBackupFile>;
    if (file.format !== 'bqv-seed-backup-v1' || typeof file.seed !== 'string') throw new Error('Unrecognized backup format (expected bqv-seed-backup-v1)');
    if (file.public !== undefined) validateBackupPublic(file.public);
    return { seed: decodeSeedWithChecksum(file.seed), ...(file.public ? { publicFields: file.public } : {}) };
  }
  return { seed: decodeSeedWithChecksum(trimmed) };
}

// ------------------------------------------------------------------ encodings

const ROOT_TYPES = [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes16' }] as const;

export function encodeVaultRoots(root: Hex, recRoot: Hex, pkSeed: Hex): Hex {
  return encodeAbiParameters(ROOT_TYPES, [root, recRoot, pkSeed]);
}

/** Offline CREATE2 prediction — must equal factory.predict() on chain (cross-checked by callers). */
export function predictVaultAddress(factory: Address, root: Hex, recRoot: Hex, pkSeed: Hex): Address {
  const encoded = encodeVaultRoots(root, recRoot, pkSeed);
  return getContractAddress({
    opcode: 'CREATE2', from: factory, salt: keccak256(encoded),
    bytecode: concatHex([ARTIFACTS.vault.bytecode, encoded]),
  });
}

export function encodeFactoryDeploy(root: Hex, recRoot: Hex, pkSeed: Hex): Hex {
  return encodeFunctionData({ abi: FACTORY_ABI, functionName: 'deploy', args: [root, recRoot, pkSeed] } as never);
}

/** Picks execute/executeFirst automatically from whether `l1` is present. */
export function encodeExecuteCall(idx: number, target: Address, value: bigint, data: Hex, sig: CchsSignature): Hex {
  const l0 = toAbiLayerSig(sig.l0);
  if (sig.l1) {
    return encodeFunctionData({ abi: VAULT_ABI, functionName: 'executeFirst', args: [target, value, data, BigInt(idx), l0, toAbiLayerSig(sig.l1)] } as never);
  }
  return encodeFunctionData({ abi: VAULT_ABI, functionName: 'execute', args: [target, value, data, BigInt(idx), l0] } as never);
}

export function encodeRecoverCall(newRoot: Hex, newRecRoot: Hex, newPkSeed: Hex, rec: LayerSig): Hex {
  return encodeFunctionData({
    abi: VAULT_ABI, functionName: 'recover',
    args: [newRoot, newRecRoot, newPkSeed, rec.wots.map(toHex), rec.auth.map(toHex)] as never,
  });
}

// -------------------------------------------------------------------- digests

function bytes20(hex: Hex): Uint8Array {
  const b = hexToBytes(hex);
  if (b.length !== 20) throw new Error('expected a 20-byte address');
  return b;
}

export interface ExecuteDigestParams {
  chainId: ChainId; vault: Address; laneNonce: bigint; idx: number;
  target: Address; value: bigint; data: Hex;
}
export function executeDigestFor(engine: Cchs, p: ExecuteDigestParams): Uint8Array {
  return engine.executeDigest({
    chainId: BigInt(p.chainId), account: bytes20(p.vault), nonce: p.laneNonce, idx: BigInt(p.idx),
    target: bytes20(p.target), value: p.value, dataHash: engine.hash(hexToBytes(p.data)),
  });
}

export interface RecoveryDigestParams {
  chainId: ChainId; vault: Address; recNonce: bigint;
  newRoot: Hex; newRecRoot: Hex; newPkSeed: Hex;
}
export function recoveryDigestFor(engine: Cchs, p: RecoveryDigestParams): Uint8Array {
  return engine.recoveryDigest({
    chainId: BigInt(p.chainId), account: bytes20(p.vault), recNonce: p.recNonce,
    newRoot: hexToBytes(p.newRoot), newRecRoot: hexToBytes(p.newRecRoot), newSeed: hexToBytes(p.newPkSeed),
  });
}

/** Decode a vault custom-error selector from a viem call error into its name. */
export function vaultErrorName(err: unknown): string | null {
  const anyErr = err as { data?: string; cause?: { data?: string; cause?: { data?: string } } };
  const data = anyErr?.data ?? anyErr?.cause?.data ?? anyErr?.cause?.cause?.data;
  if (typeof data !== 'string' || data.length < 10) return null;
  const selectors = new Map<string, string>();
  for (const item of VAULT_ABI as { type: string; name?: string; inputs?: { type: string }[] }[]) {
    if (item.type === 'error' && item.name) {
      selectors.set(toFunctionSelector(`${item.name}(${(item.inputs ?? []).map((i) => i.type).join(',')})`), item.name);
    }
  }
  return selectors.get(data.slice(0, 10)) ?? `unknown error ${data.slice(0, 10)}`;
}
