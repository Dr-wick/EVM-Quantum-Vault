/**
 * EVM Quantum Vault: K-20 hash-signature core.
 * Adapted from Aegis Protocol, commit 71e4070.
 *
 * MIT License
 *
 * Copyright (c) 2026 Aegis Protocol contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { hmac } from '@noble/hashes/hmac';
import { concatBytes } from '@noble/hashes/utils';

export const W = 16;
export const LEN = 67;
export const H = 10;
export const LEAVES = 1 << H;
export const CAPACITY = 1 << (2 * H);
export const REC_H = 8;

export type HashFn = (data: Uint8Array) => Uint8Array;

const enc = new TextEncoder();
const CSUM_MAX = 64 * (W - 1); // 960

// ------------------------------------------------------------------ utils

function u8(n: number): Uint8Array { return Uint8Array.of(n & 0xff); }
function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0); return b;
}
function u64be(n: bigint): Uint8Array {
  if (n < 0n || n > 0xffffffffffffffffn) throw new Error('u64 out of range');
  const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n); return b;
}
function u256be(n: bigint): Uint8Array {
  if (n < 0n || n >= (1n << 256n)) throw new Error('u256 out of range');
  const b = new Uint8Array(32); let x = n;
  for (let i = 31; i >= 0; i--) { b[i] = Number(x & 0xffn); x >>= 8n; }
  return b;
}
export function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0;
}
export const toHex = (b: Uint8Array): `0x${string}` =>
  ('0x' + Array.from(b, x => x.toString(16).padStart(2, '0')).join('')) as `0x${string}`;

/** Bytes of the per-tree public seed carried in every ADRS (spec §2.2). */
export const SEED_BYTES = 16;

/**
 * ADRS = layer(1) ‖ treeIdx(8) ‖ type(1) ‖ leafIdx(4) ‖ chainIdx(1) ‖ step(1) ‖ pkSeed(16)
 *
 * `seed` is the tree's public seed (`pkSeed`, 16 bytes): it makes every hash
 * call of one key tree a different function from the same position in any
 * other tree (other account, chain or epoch), which is what the SPHINCS+
 * multi-target argument needs. It fills what used to be zero padding, so the
 * hash input length is unchanged.
 */
export function adrs(seed: Uint8Array, layer: number, treeIdx: bigint, typ: number, leafIdx: number, chainIdx: number, step: number): Uint8Array {
  if (seed.length !== SEED_BYTES) throw new Error('pkSeed must be 16 bytes');
  const out = new Uint8Array(32);
  out[0] = layer & 0xff;
  out.set(u64be(treeIdx), 1);
  out[9] = typ & 0xff;
  out.set(u32be(leafIdx), 10);
  out[14] = chainIdx & 0xff;
  out[15] = step & 0xff;
  out.set(seed, 16);
  return out;
}

/** 64 base-16 message digits ‖ 3 base-16 checksum digits. Matches Solidity `_digits`. */
export function digits(m: Uint8Array): Uint8Array {
  if (m.length !== 32) throw new Error('digest must be 32 bytes');
  const d = new Uint8Array(LEN);
  let csum = 0;
  for (let i = 0; i < 32; i++) {
    const hi = m[i] >> 4, lo = m[i] & 0x0f;
    d[2 * i] = hi; d[2 * i + 1] = lo;
    csum += (W - 1 - hi) + (W - 1 - lo);
  }
  if (csum > CSUM_MAX) throw new Error('unreachable');
  d[64] = (csum >> 8) & 0x0f; d[65] = (csum >> 4) & 0x0f; d[66] = csum & 0x0f;
  return d;
}

// ------------------------------------------------------------------- types

export interface CchsKey { master: Uint8Array; recoveryMaster?: Uint8Array } // independent 32-byte spending and recovery secrets
/** Public key: both roots and the 16-byte public seed every hash of the tree is tweaked with. */
export interface CchsPublic { root: Uint8Array; recRoot: Uint8Array; seed: Uint8Array }
export interface Tree { height: number; levels: Uint8Array[][]; root: Uint8Array }
export interface LayerSig { wots: Uint8Array[]; auth: Uint8Array[] }
export interface CchsSignature { l0: LayerSig; l1?: LayerSig; idx: number }

/**
 * Inner-key derivation: HKDF-SHA256(master, salt = ∅, info).
 * Written out as Extract + Expand so Extract (the PRK) is computed once per master.
 * A single 32-byte block of output is Expand(PRK, info) = HMAC(PRK, info ‖ 0x01).
 * The result is byte-identical to `hkdf(sha256, master, undefined, info, 32)`.
 */
type Hmac = ReturnType<typeof hmac.create>;
const expandCache = new WeakMap<Uint8Array, Hmac>();
/** HMAC(PRK, ·) with the key schedule already absorbed; cloned per call. */
function expanderOf(master: Uint8Array): Hmac {
  let h = expandCache.get(master);
  if (!h) {
    const prk = hmac(sha256, new Uint8Array(32), master);
    h = hmac.create(sha256, prk);
    expandCache.set(master, h);
  }
  return h;
}
/** The inner K-20 labels remain compatible with published primitive vectors.
 * Project, deployment, chain, account and epoch separation happens in derive.ts. */
const SK_INFO_PREFIX = enc.encode('cchs/sk/k');
const skInfo = new Uint8Array(SK_INFO_PREFIX.length + 1 + 8 + 4 + 1 + 1);
skInfo.set(SK_INFO_PREFIX);
skInfo[skInfo.length - 1] = 1;
export function sk(key: CchsKey, layer: number, treeIdx: bigint, leafIdx: number, chainIdx: number): Uint8Array {
  const master = layer === 0xff ? (key.recoveryMaster ?? key.master) : key.master;
  if (master.length !== 32) throw new Error('master must be 32 bytes');
  const o = SK_INFO_PREFIX.length;
  skInfo[o] = layer;
  skInfo.set(u64be(treeIdx), o + 1);
  skInfo.set(u32be(leafIdx), o + 9);
  skInfo[o + 13] = chainIdx;
  return expanderOf(master)._cloneInto().update(skInfo).digest();
}
const SEED_INFO = concatBytes(enc.encode('cchs/pkseed/k'), u8(1));
const seedCache = new WeakMap<Uint8Array, Uint8Array>();
/** One public seed for both trees; recovery secret material is independently derived. */
export function pkSeed(key: CchsKey): Uint8Array {
  if (key.master.length !== 32) throw new Error('master must be 32 bytes');
  let s = seedCache.get(key.master);
  if (!s) {
    s = expanderOf(key.master)._cloneInto().update(SEED_INFO).digest().slice(0, SEED_BYTES);
    seedCache.set(key.master, s);
  }
  return s;
}

// ------------------------------------------------------------- the scheme

export function makeCchs(hash: HashFn) {
  const F = (a: Uint8Array, x: Uint8Array) => hash(concatBytes(a, x)); // spec form; hot path uses chainSteps

  // Zero-allocation hot path: one 64-byte scratch for chain steps, one 96-byte
  // scratch for Merkle nodes, one 2176-byte scratch for leaf compression.
  const scratch64 = new Uint8Array(64);
  const scratch96 = new Uint8Array(96);
  const scratchLeaf = new Uint8Array(32 + LEN * 32);

  const seedOf = (key: CchsKey) => pkSeed(key);

  /** Apply chain steps [from, to) for chain `c` of the WOTS+ key at (layer, treeIdx, leafIdx). */
  function chainSteps(seed: Uint8Array, layer: number, treeIdx: bigint, leafIdx: number, c: number, from: number, to: number, x: Uint8Array): Uint8Array {
    if (from >= to) return x;
    scratch64.set(adrs(seed, layer, treeIdx, 0x00, leafIdx, c, 0), 0);
    for (let s = from; s < to; s++) {
      scratch64[15] = s;
      scratch64.set(x, 32);
      x = hash(scratch64);
    }
    return x;
  }

  function wotsChainEnds(key: CchsKey, layer: number, treeIdx: bigint, leafIdx: number): Uint8Array[] {
    const seed = seedOf(key);
    const pks: Uint8Array[] = new Array(LEN);
    for (let c = 0; c < LEN; c++) {
      pks[c] = chainSteps(seed, layer, treeIdx, leafIdx, c, 0, W - 1, sk(key, layer, treeIdx, leafIdx, c));
    }
    return pks;
  }

  function leafFromEnds(seed: Uint8Array, layer: number, treeIdx: bigint, leafIdx: number, ends: Uint8Array[]): Uint8Array {
    scratchLeaf.set(adrs(seed, layer, treeIdx, 0x01, leafIdx, 0, 0), 0);
    for (let c = 0; c < LEN; c++) scratchLeaf.set(ends[c], 32 + c * 32);
    return hash(scratchLeaf);
  }

  function nodeHash(seed: Uint8Array, layer: number, treeIdx: bigint, parentPos: number, level: number, left: Uint8Array, right: Uint8Array): Uint8Array {
    scratch96.set(adrs(seed, layer, treeIdx, 0x02, parentPos, level, 0), 0);
    scratch96.set(left, 32);
    scratch96.set(right, 64);
    return hash(scratch96);
  }

  function wotsLeaf(key: CchsKey, layer: number, treeIdx: bigint, leafIdx: number): Uint8Array {
    return leafFromEnds(seedOf(key), layer, treeIdx, leafIdx, wotsChainEnds(key, layer, treeIdx, leafIdx));
  }

  /** Leaves for [from, to) of tree (layer, treeIdx) — unit of work for parallel keygen. */
  function leavesRange(key: CchsKey, layer: number, treeIdx: bigint, from: number, to: number): Uint8Array[] {
    const out: Uint8Array[] = new Array(to - from);
    for (let j = from; j < to; j++) out[j - from] = wotsLeaf(key, layer, treeIdx, j);
    return out;
  }

  function buildTreeFromLeaves(seed: Uint8Array, layer: number, treeIdx: bigint, leaves: Uint8Array[]): Tree {
    const height = Math.log2(leaves.length);
    if (!Number.isInteger(height)) throw new Error('leaf count must be a power of two');
    const levels: Uint8Array[][] = [leaves];
    for (let k = 0; k < height; k++) {
      const prev = levels[k];
      const next: Uint8Array[] = new Array(prev.length / 2);
      for (let i = 0; i < next.length; i++) {
        next[i] = nodeHash(seed, layer, treeIdx, i, k, prev[2 * i], prev[2 * i + 1]);
      }
      levels.push(next);
    }
    return { height, levels, root: levels[height][0] };
  }

  function buildTree(key: CchsKey, layer: number, treeIdx: bigint, height: number): Tree {
    return buildTreeFromLeaves(seedOf(key), layer, treeIdx, leavesRange(key, layer, treeIdx, 0, 1 << height));
  }

  function authPath(t: Tree, leafIdx: number): Uint8Array[] {
    const path: Uint8Array[] = [];
    let pos = leafIdx;
    for (let k = 0; k < t.height; k++) { path.push(t.levels[k][pos ^ 1].slice()); pos >>= 1; }
    return path;
  }

  function rootFromPath(seed: Uint8Array, layer: number, treeIdx: bigint, leaf: Uint8Array, leafIdx: number, path: Uint8Array[]): Uint8Array {
    let r = leaf, pos = leafIdx;
    for (let k = 0; k < path.length; k++) {
      r = (pos & 1) === 0 ? nodeHash(seed, layer, treeIdx, pos >> 1, k, r, path[k]) : nodeHash(seed, layer, treeIdx, pos >> 1, k, path[k], r);
      pos >>= 1;
    }
    return r;
  }

  /** Top tree (layer 1, 2^10 WOTS+ keys) + recovery tree (layer 0xFF, 2^8). ~1.3M hashes. */
  function keygen(key: CchsKey, cache?: Map<string, Tree>): CchsPublic {
    const top = buildTree(key, 1, 0n, H);
    const rec = buildTree(key, 0xff, 0n, REC_H);
    cache?.set('1/0', top); cache?.set('ff/0', rec);
    return { root: top.root, recRoot: rec.root, seed: seedOf(key).slice() };
  }

  function wotsSign(key: CchsKey, layer: number, treeIdx: bigint, leafIdx: number, m: Uint8Array): Uint8Array[] {
    const d = digits(m);
    const seed = seedOf(key);
    const out: Uint8Array[] = new Array(LEN);
    for (let c = 0; c < LEN; c++) {
      out[c] = chainSteps(seed, layer, treeIdx, leafIdx, c, 0, d[c], sk(key, layer, treeIdx, leafIdx, c));
    }
    return out;
  }

  function wotsEndsFromSig(seed: Uint8Array, layer: number, treeIdx: bigint, leafIdx: number, m: Uint8Array, sig: Uint8Array[]): Uint8Array[] {
    const d = digits(m);
    const out: Uint8Array[] = new Array(LEN);
    for (let c = 0; c < LEN; c++) {
      out[c] = chainSteps(seed, layer, treeIdx, leafIdx, c, d[c], W - 1, sig[c]);
    }
    return out;
  }

  /**
   * Sign digest `m` at leaf `idx` (read from chain). Includes the top-layer
   * proof unless `subtreeCached`. `treeCache` avoids tree rebuilds (pure optimisation).
   */
  function sign(key: CchsKey, idx: number, m: Uint8Array, subtreeCached: boolean, treeCache?: Map<string, Tree>): CchsSignature {
    if (!Number.isSafeInteger(idx) || idx < 0 || idx >= CAPACITY) throw new Error('index exhausted');
    const treeIdx = BigInt(idx >> H);
    const leafIdx = idx & (LEAVES - 1);

    const ck = `0/${treeIdx}`;
    let bottom = treeCache?.get(ck);
    if (!bottom) { bottom = buildTree(key, 0, treeIdx, H); treeCache?.set(ck, bottom); }

    const l0: LayerSig = { wots: wotsSign(key, 0, treeIdx, leafIdx, m), auth: authPath(bottom, leafIdx) };
    if (subtreeCached) return { l0, idx };

    let top = treeCache?.get('1/0');
    if (!top) { top = buildTree(key, 1, 0n, H); treeCache?.set('1/0', top); }
    const topLeaf = Number(treeIdx);
    const l1: LayerSig = { wots: wotsSign(key, 1, 0n, topLeaf, bottom.root), auth: authPath(top, topLeaf) };
    return { l0, l1, idx };
  }

  /** Local verifier mirroring the contract. Returns the bottom root to cache, or throws. */
  function verify(pub: CchsPublic, idx: number, m: Uint8Array, s: CchsSignature, cachedBottomRoot?: Uint8Array): Uint8Array {
    if (!Number.isSafeInteger(idx) || idx < 0 || idx >= CAPACITY || s.idx !== idx) throw new Error('index mismatch');
    validatePublic(pub); validateLayer(s.l0, H); if (s.l1) validateLayer(s.l1, H);
    if (cachedBottomRoot && cachedBottomRoot.length !== 32) throw new Error('bad cached root');
    const seed = pub.seed;
    const treeIdx = BigInt(idx >> H);
    const leafIdx = idx & (LEAVES - 1);
    const ends0 = wotsEndsFromSig(seed, 0, treeIdx, leafIdx, m, s.l0.wots);
    const r0 = rootFromPath(seed, 0, treeIdx, leafFromEnds(seed, 0, treeIdx, leafIdx, ends0), leafIdx, s.l0.auth);
    if (cachedBottomRoot) {
      if (!eq(cachedBottomRoot, r0)) throw new Error('bad subtree root');
      return r0;
    }
    if (!s.l1) throw new Error('missing top layer');
    const topLeaf = Number(treeIdx);
    const ends1 = wotsEndsFromSig(seed, 1, 0n, topLeaf, r0, s.l1.wots);
    const r1 = rootFromPath(seed, 1, 0n, leafFromEnds(seed, 1, 0n, topLeaf, ends1), topLeaf, s.l1.auth);
    if (!eq(r1, pub.root)) throw new Error('bad top root');
    return r0;
  }

  /** Recovery-tree check mirroring the contract: returns true when `s` is a valid leaf `recNonce` signature on `m`. */
  function verifyRecovery(pub: CchsPublic, recNonce: number, m: Uint8Array, s: LayerSig): boolean {
    if (!Number.isSafeInteger(recNonce) || recNonce < 0 || recNonce >= (1 << REC_H)) throw new Error('bad recovery index');
    validatePublic(pub); validateLayer(s, REC_H);
    const ends = wotsEndsFromSig(pub.seed, 0xff, 0n, recNonce, m, s.wots);
    const r = rootFromPath(pub.seed, 0xff, 0n, leafFromEnds(pub.seed, 0xff, 0n, recNonce, ends), recNonce, s.auth);
    return eq(r, pub.recRoot);
  }

  function signRecovery(key: CchsKey, recNonce: number, m: Uint8Array, treeCache?: Map<string, Tree>): LayerSig {
    if (!Number.isSafeInteger(recNonce) || recNonce < 0 || recNonce >= (1 << REC_H)) throw new Error('bad recovery index');
    let rec = treeCache?.get('ff/0');
    if (!rec) { rec = buildTree(key, 0xff, 0n, REC_H); treeCache?.set('ff/0', rec); }
    return { wots: wotsSign(key, 0xff, 0n, recNonce, m), auth: authPath(rec, recNonce) };
  }

  /**
   * M = hash("BQV_EXECUTE_V1" ‖ chainId(32) ‖ account(20) ‖ nonce(8) ‖ idx(8) ‖ target(20) ‖ value(32) ‖ keccak256(data))
   * Mirrors abi.encodePacked in AegisCCHSBase._digest. `dataHash` = keccak256(data).
   */
  function executeDigest(p: { chainId: bigint; account: Uint8Array; nonce: bigint; idx: bigint; target: Uint8Array; value: bigint; dataHash: Uint8Array }): Uint8Array {
    validateDigestContext(p.chainId, p.account);
    if (p.target.length !== 20 || p.dataHash.length !== 32) throw new Error('bad call encoding');
    return hash(concatBytes(
      enc.encode('BQV_EXECUTE_V1'), u256be(p.chainId), p.account, u64be(p.nonce), u64be(p.idx),
      p.target, u256be(p.value), p.dataHash,
    ));
  }

  /**
   * Recovery message binds the whole new public key: both roots and the new seed.
   * hash("BQV_RECOVER_V1" ‖ chainId(32) ‖ account(20) ‖ recNonce(8) ‖ newRoot ‖ newRecRoot ‖ newSeed(16))
   */
  function recoveryDigest(p: { chainId: bigint; account: Uint8Array; recNonce: bigint; newRoot: Uint8Array; newRecRoot: Uint8Array; newSeed: Uint8Array }): Uint8Array {
    validateDigestContext(p.chainId, p.account);
    if (p.newRoot.length !== 32 || p.newRecRoot.length !== 32) throw new Error('bad recovery roots');
    if (p.newSeed.length !== SEED_BYTES) throw new Error('newSeed must be 16 bytes');
    return hash(concatBytes(
      enc.encode('BQV_RECOVER_V1'), u256be(p.chainId), p.account, u64be(p.recNonce), p.newRoot, p.newRecRoot, p.newSeed,
    ));
  }

  return {
    hash, F, seedOf,
    wotsLeaf, leavesRange, buildTree, buildTreeFromLeaves, authPath, rootFromPath,
    keygen, sign, verify, verifyRecovery, signRecovery, executeDigest, recoveryDigest,
  };
}

export type Cchs = ReturnType<typeof makeCchs>;

/** Keccak-256 K-20 engine. Private primitives must only sign journal reservations. */
export const cchsK: Cchs = makeCchs(keccak_256);

// ------------------------------------------------------ ABI encoding helpers

export function toAbiLayerSig(l: LayerSig): { wots: `0x${string}`[]; auth: `0x${string}`[] } {
  return { wots: l.wots.map(toHex), auth: l.auth.map(toHex) };
}

export const EMPTY_LAYER_SIG = {
  wots: Array<`0x${string}`>(LEN).fill(('0x' + '00'.repeat(32)) as `0x${string}`),
  auth: Array<`0x${string}`>(H).fill(('0x' + '00'.repeat(32)) as `0x${string}`),
};

export function signatureBytes(s: CchsSignature): number {
  const layer = (LEN + H) * 32;
  return s.l1 ? 2 * layer : layer;
}

function validateLayer(s: LayerSig, height: number): void {
  if (s.wots.length !== LEN || s.auth.length !== height || [...s.wots, ...s.auth].some(x => x.length !== 32)) throw new Error('bad signature shape');
}
function validatePublic(p: CchsPublic): void {
  if (p.root.length !== 32 || p.recRoot.length !== 32 || p.seed.length !== SEED_BYTES) throw new Error('bad public key');
}
function validateDigestContext(chainId: bigint, account: Uint8Array): void {
  if (chainId !== 56n && chainId !== 97n) throw new Error('only BSC mainnet or testnet is supported');
  if (account.length !== 20) throw new Error('account must be 20 bytes');
}
