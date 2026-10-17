// SPDX-License-Identifier: MIT
/**
 * Vault worker: holds the real backup seed (memory only) and performs key
 * derivation, keygen, signing and local verification with the WASM engine.
 * Secrets never leave this worker except:
 *  - the seed once, on generate, so the page can show/download the backup;
 *  - public keys and signatures (public by design).
 * The signing journal stays on the main thread (single writer); this worker
 * only does cryptography. All requests run serialized on one queue.
 */
import { fastCchs } from './crypto/fast';
import { deriveAccountKey } from './crypto/derive';
import { signatureBytes, toHex, type Cchs, type CchsKey, type CchsPublic, type Tree } from './crypto/cchs';
import type { VaultWorkerRequest, VaultWorkerResponse, WireScope } from './vault/types';

interface Context { engine: Cchs; key: CchsKey; pub: CchsPublic; trees: Map<string, Tree>; epoch: string; seed: Uint8Array }

let enginePromise: ReturnType<typeof fastCchs> | undefined;
let pendingSeed: Uint8Array | undefined;
let active: Context | undefined;
let pendingContext: Context | undefined;

const send = (message: VaultWorkerResponse) => self.postMessage(message);
const progress = (id: number, label: string) => send({ id, type: 'progress', label });

async function buildContext(seed: Uint8Array, scope: WireScope): Promise<Context> {
  const engine = await (enginePromise ??= fastCchs());
  const key = deriveAccountKey(seed, {
    chainId: scope.chainId,
    factory: scope.factory as `0x${string}`,
    deploymentNamespace: scope.namespace,
    accountIndex: BigInt(scope.accountIndex),
    epoch: BigInt(scope.epoch),
  });
  const trees = new Map<string, Tree>();
  const pub = engine.keygen(key, trees); // top + recovery trees (~1.3M hashes)
  trees.set('0/0', engine.buildTree(key, 0, 0n, 10)); // pre-expand the first subtree for a fast first spend
  return { engine, key, pub, trees, epoch: scope.epoch, seed: seed.slice() };
}

function requireRoot(expected: string): Context {
  if (!active || typeof expected !== 'string' || toHex(active.pub.root).toLowerCase() !== expected.toLowerCase()) throw new Error('The loaded key does not match this vault. Signing stopped; import the correct backup.');
  return active;
}

function erase(context: Context | undefined): void {
  context?.key.master.fill(0); context?.key.recoveryMaster?.fill(0); context?.seed.fill(0);
  context?.trees.clear();
}
function clear(): void {
  pendingSeed?.fill(0); pendingSeed = undefined;
  erase(active); erase(pendingContext); active = undefined; pendingContext = undefined;
}

async function run(request: VaultWorkerRequest): Promise<void> {
  const { id } = request;
  switch (request.type) {
    case 'generate': {
      clear();
      pendingSeed = crypto.getRandomValues(new Uint8Array(32));
      send({ id, type: 'seed', seedHex: toHex(pendingSeed) });
      return;
    }
    case 'import': {
      clear();
      const bytes = fromHex(request.seedHex, 32);
      pendingSeed = bytes;
      send({ id, type: 'imported' });
      return;
    }
    case 'fresh-seed': {
      send({ id, type: 'seed', seedHex: toHex(crypto.getRandomValues(new Uint8Array(32))) });
      return;
    }
    case 'stage-recovery': {
      const current = requireRoot(request.expectedRoot);
      const seed = fromHex(request.seedHex, 32);
      if (toHex(seed) === toHex(current.seed)) throw new Error('Key rotation requires an independent, newly generated random backup seed');
      erase(pendingContext);
      pendingContext = await buildContext(seed, request.scope);
      seed.fill(0);
      const p = pendingContext.pub;
      send({ id, type: 'keygen', keygenMs: 0, publicKey: { root: toHex(p.root), recRoot: toHex(p.recRoot), pkSeed: toHex(p.seed) } });
      return;
    }
    case 'keygen': {
      if (!pendingSeed) throw new Error('Import or generate a seed first');
      progress(id, 'Deriving keys and building authentication trees (typically 1–2 seconds)…');
      const t0 = performance.now();
      const context = await buildContext(pendingSeed, request.scope);
      if (request.keepCurrent) pendingContext = context;
      else { erase(active); erase(pendingContext); active = context; pendingContext = undefined; }
      pendingSeed.fill(0); pendingSeed = undefined;
      send({
        id, type: 'keygen', keygenMs: performance.now() - t0,
        publicKey: { root: toHex(context.pub.root), recRoot: toHex(context.pub.recRoot), pkSeed: toHex(context.pub.seed) },
      });
      return;
    }
    case 'activate': {
      if (!pendingContext) throw new Error('No new key is waiting for activation');
      erase(active); active = pendingContext; pendingContext = undefined;
      send({ id, type: 'activated' });
      return;
    }
    case 'sign': {
      requireRoot(request.expectedRoot);
      if (!active) throw new Error('Vault key is not loaded');
      const treeIdx = BigInt(request.idx >> 10);
      if (!active.trees.get(`0/${treeIdx}`)) progress(id, 'Expanding the subtree (typically 1–2 seconds on first use)…');
      else progress(id, 'Generating signature…');
      const digest = fromHex(request.digestHex, 32);
      const t0 = performance.now();
      const sig = active.engine.sign(active.key, request.idx, digest, !request.needsTop, active.trees);
      const bottom = active.trees.get(`0/${treeIdx}`);
      active.engine.verify(active.pub, request.idx, digest, sig, sig.l1 ? undefined : bottom?.root); // throws on any inconsistency
      send({
        id, type: 'signed', signMs: performance.now() - t0, bytes: signatureBytes(sig),
        l0: { wots: sig.l0.wots, auth: sig.l0.auth },
        l1: sig.l1 ? { wots: sig.l1.wots, auth: sig.l1.auth } : null,
      });
      return;
    }
    case 'recover-sign': {
      requireRoot(request.expectedRoot);
      if (!active) throw new Error('Vault key is not loaded');
      progress(id, 'Signing with the recovery key…');
      const digest = fromHex(request.digestHex, 32);
      const recNonce = Number(request.recNonce);
      const t0 = performance.now();
      const rec = active.engine.signRecovery(active.key, recNonce, digest);
      if (!active.engine.verifyRecovery(active.pub, recNonce, digest, rec)) throw new Error('Local recovery signature verification failed; operation stopped');
      send({ id, type: 'recover-signed', wots: rec.wots, auth: rec.auth, signMs: performance.now() - t0 });
      return;
    }
    case 'lock': {
      clear();
      send({ id, type: 'locked' });
      return;
    }
    default:
      throw new Error(`unknown request ${(request as { type: string }).type}`);
  }
}

function fromHex(hex: string, length: number): Uint8Array {
  if (typeof hex !== 'string' || !new RegExp(`^(0x)?[0-9a-fA-F]{${length * 2}}$`).test(hex)) throw new Error('Invalid key or digest encoding');
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

let queue: Promise<void> = Promise.resolve();
self.onmessage = (event: MessageEvent<VaultWorkerRequest>) => {
  const request = event.data;
  queue = queue.then(() => run(request)).catch((error: unknown) => {
    send({ id: request.id, type: 'error', message: error instanceof Error ? error.message : String(error) });
  });
};
