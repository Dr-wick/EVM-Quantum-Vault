import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { IDBFactory } from 'fake-indexeddb';
import { bytesToHex, type Hex } from 'viem';
import { openJournal } from '../src/crypto/journal';
import { encodeSeedWithChecksum, parseSeedBackup, seedBackupFile, predictVaultAddress } from '../src/vault/ops';
import { verifyRecoveryBackup, recoveryState } from '../src/vault/recovery';
import { fastCchs } from '../src/crypto/fast';
import type { VaultRecord, VaultWorkerRequest, VaultWorkerResponse } from '../src/vault/types';
import type { VaultKeyState } from '../src/vault/chain';
import hashWasm from 'hash-wasm';

const store = new Map<string, string>();
Object.defineProperty(globalThis, 'localStorage', { value: { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => store.set(k, v) }, configurable: true });
Object.defineProperty(globalThis, 'indexedDB', { value: new IDBFactory(), configurable: true });
let state: VaultKeyState;
let mode: 'reject' | 'pending' | 'unknown' = 'pending';
let receiptStatus: 'success' | 'reverted' | null = null;
let lookup: { to: Hex; input: Hex; value: bigint };
let waitHook: (() => void) | undefined;
let sent = 0, signed = 0;
let workerHandler: ((e: { data: VaultWorkerRequest }) => void) | undefined;
const hash = `0x${'ab'.repeat(32)}` as Hex;
const rpc = {
  getBlockNumber: async () => 1n,
  getCode: async () => '0x01',
  getTransactionReceipt: async () => { if (!receiptStatus) throw new Error('pending'); return { status: receiptStatus }; },
  getTransaction: async () => lookup,
  estimateGas: async () => 300000n,
  readContract: async ({ functionName, address, args }: { functionName: string; address: Hex; args: Hex[] }) => functionName === 'predict'
    ? predictVaultAddress(address, args[0], args[1], args[2]) : state[functionName as keyof VaultKeyState],
};
// Node's experimental module-mocking loader needs explicit CJS named exports;
// browser Vite and the ordinary crypto tests use the unchanged library import.
mock.module('hash-wasm', { namedExports: { createKeccak: hashWasm.createKeccak } });
mock.module('../src/services.ts', { namedExports: {
  NETWORKS: { 56: { explorer: 'https://example.invalid' }, 97: { explorer: 'https://example.invalid' } },
  getPublicClient: () => rpc, ensureWalletChain: async () => {}, waitForReceipt: async () => { waitHook?.(); return null; },
  sendTransaction: async () => { sent++; if (mode === 'reject') throw Object.assign(new Error('rejected'), { code: 4001 });
    if (mode === 'unknown') throw new Error('connection interrupted'); return hash; },
} });

/** Executes the actual worker module against synthetic seeds; no browser or network. */
class TestWorker {
  onmessage?: (e: { data: VaultWorkerResponse }) => void;
  onerror?: () => void;
  terminated = false;
  scope: { postMessage: (r: VaultWorkerResponse) => void; onmessage?: (e: { data: VaultWorkerRequest }) => void };
  ready: Promise<unknown>;
  constructor() {
    this.scope = { postMessage: data => { if (!this.terminated) this.onmessage?.({ data }); } };
    Object.defineProperty(globalThis, 'self', { value: this.scope, configurable: true });
    this.ready = import('../src/vault.worker').then(() => {
      workerHandler ??= this.scope.onmessage;
      this.scope.onmessage = workerHandler;
    });
  }
  postMessage(data: VaultWorkerRequest) {
    if (data.type === 'recover-sign' || data.type === 'sign') signed++;
    void this.ready.then(() => this.scope.onmessage?.({ data }));
  }
  terminate() { this.scope.onmessage?.({ data: { id: -1, type: 'lock' } }); this.terminated = true; }
}
Object.defineProperty(globalThis, 'Worker', { value: TestWorker, configurable: true });
const client = await import('../src/vault/client');

test('actual worker + client: independent seed, durable recovery, reload and old-backup rejection', async t => {
  const seed = await client.generateSeedInWorker();
  const pk = await client.keygenFor(56, '0x0000000000000000000000000000000000000011', 'bqv-test/v1', '0', '0');
  state = { ...pk, epoch: 0n, recNonce: 0n };
  const record: VaultRecord = { chainId: 56, factory: '0x0000000000000000000000000000000000000011',
    vault: '0x0000000000000000000000000000000000000022', namespace: 'bqv-test/v1', accountIndex: '0',
    createdAt: '', currentEpoch: '0', epochs: { '0': pk }, txs: [] };
  client.saveRecord(record); await client.initializeJournal(record, 0);
  await t.test('worker rejects wrong root and same-seed recovery', async () => {
    await assert.rejects(client.requestVault({ type: 'sign', expectedRoot: `0x${'00'.repeat(32)}`, idx: 0, digestHex: hash, needsTop: true }), /does not match/);
    await assert.rejects(client.prepareRecovery(record, seed as Hex), /independent/);
    await assert.rejects(client.importSeedToWorker('zz'.repeat(32)), /Invalid key or digest encoding/);
    await client.importSeedToWorker(seed);
    await client.keygenFor(56, record.factory, record.namespace, '0', '0');
  });
  const newSeed = await client.generateRecoverySeed();
  const intent = await client.prepareRecovery(record, newSeed as Hex);
  const backup = seedBackupFile(new Uint8Array(Buffer.from(newSeed.slice(2), 'hex')), {
    chainId: 56, factory: record.factory, vault: record.vault, namespace: record.namespace,
    accountIndex: '0', epoch: intent.newEpoch, ...intent.newPublicKey,
  });
  await t.test('preparing alone neither signs nor commits; saved intent contains no seed', async () => {
    assert.equal(record.pendingRecovery, undefined);
    await client.saveRecovery(record, intent);
    assert.ok(record.pendingRecovery);
    const saved = store.get('bqv.vaults.v1')!;
    assert.ok(!saved.includes(seed.slice(2)) && !saved.includes(newSeed.slice(2)));
    assert.notEqual(intent.newPublicKey.root, pk.root);
    const engine = await fastCchs();
    verifyRecoveryBackup(JSON.stringify(backup), record, intent, engine);
    assert.throws(() => verifyRecoveryBackup('{broken', record, intent, engine));
    const wrong = { ...backup, seed: encodeSeedWithChecksum(new Uint8Array(32).fill(77)) };
    assert.throws(() => verifyRecoveryBackup(JSON.stringify(wrong), record, intent, engine), /does not match/);
  });
  await t.test('wallet rejection and retry reuse the identical recovery signature', async () => {
    mode = 'reject'; const before = signed;
    await assert.rejects(client.recoverVault({ chainId: 56, record, from: record.factory }), /rejected/);
    assert.equal(signed, before + 1); assert.equal(intent.submissionUncertain, false);
    const payload = intent.calldata; mode = 'pending';
    const result = await client.recoverVault({ chainId: 56, record, from: record.factory });
    assert.equal(result.pending, true); assert.equal(signed, before + 1); assert.equal(intent.calldata, payload);
  });
  await t.test('pending state after reload checks without signing or resending', async () => {
    await client.lockKeyMaterial(); const before = sent;
    const restored = client.recordForChain(56)!;
    assert.equal((await client.recoverVault({ chainId: 56, record: restored, from: record.factory })).pending, true);
    assert.equal(sent, before);
  });
  await t.test('ordinary pending transactions reconcile success/revert without resending', async () => {
    const before = sent;
    record.txs.push({ label: 'deposit', hash, status: 'pending' });
    client.saveRecord(record);
    receiptStatus = 'success'; await client.reconcileTransactions(record);
    assert.ok(record.txs.every(tx => tx.status !== 'pending'));
    record.txs.push({ label: 'execution', hash, status: 'pending' });
    client.saveRecord(record);
    receiptStatus = 'reverted'; await client.reconcileTransactions(record);
    assert.equal(record.txs.at(-1)?.status, 'reverted'); assert.equal(sent, before);
    receiptStatus = null;
  });
  await t.test('reverted recovery retries only its saved payload; conflicting chain state stops', async () => {
    const count = signed, data = intent.calldata;
    receiptStatus = 'reverted';
    await client.recoverVault({ chainId: 56, record, from: record.factory });
    assert.equal(intent.calldata, data); assert.equal(signed, count);
    receiptStatus = null;
    assert.throws(() => recoveryState(record, { ...state, epoch: 7n }), /does not match/);
  });
  await t.test('confirmation reconciles once and never resets a consumed new-key journal', async () => {
    const journal = await openJournal();
    const scope = client.journalScopeFor(record, 1);
    assert.equal((await journal.reserve(scope)).index, 0);
    state = { ...intent.newPublicKey, epoch: 1n, recNonce: 1n };
    assert.equal(await client.reconcileRecovery(record), true);
    assert.equal(await client.reconcileRecovery(record), false);
    assert.equal(record.currentEpoch, '1'); assert.equal(record.pendingRecovery, undefined);
    assert.equal((await journal.reserve(scope)).index, 1); journal.close();
  });
  await t.test('nonzero-epoch backup imports at the original vault address; old seed fails', async () => {
    const parsed = parseSeedBackup(JSON.stringify(backup));
    const adopted = await client.adoptFromBackup(56, parsed.publicFields!, intent.newPublicKey);
    assert.equal(adopted.vault, record.vault); assert.equal(adopted.currentEpoch, '1');
    await client.importSeedToWorker(seed);
    const old = await client.keygenFor(56, record.factory, record.namespace, '0', '1');
    await assert.rejects(client.adoptFromBackup(56, parsed.publicFields!, old), /does not contain/);
  });
  await t.test('uncertain submission is preserved and blocks another send', async () => {
    await client.importSeedToWorker(newSeed);
    await client.keygenFor(56, record.factory, record.namespace, '0', '1');
    const thirdSeed = await client.generateRecoverySeed();
    const second = await client.prepareRecovery(record, thirdSeed as Hex);
    await client.saveRecovery(record, second); mode = 'unknown';
    await assert.rejects(client.recoverVault({ chainId: 56, record, from: record.factory }), /interrupted/);
    const before = sent;
    await assert.rejects(client.recoverVault({ chainId: 56, record, from: record.factory }), /uncertain/);
    assert.equal(sent, before); assert.equal(second.submissionUncertain, true);
    lookup = { to: record.vault, input: '0x00', value: 0n };
    await assert.rejects(client.attachRecoveryTransaction(record, hash), /does not match/);
    lookup = { to: record.vault, input: second.calldata!, value: 0n };
    await client.attachRecoveryTransaction(record, hash);
    assert.equal(second.hash, hash); assert.equal(second.submissionUncertain, false); assert.equal(sent, before);
  });
  await t.test('creation publishes its pending record before waiting for a receipt', async () => {
    mode = 'pending'; let saved = false;
    waitHook = () => assert.equal(saved, true);
    const result = await client.deployVault({ chainId: 56, factory: record.factory, publicKey: pk,
      fundValueWei: 0n, from: record.factory, onSubmitted: async outcome => { saved = true; assert.equal(outcome.pending, true); assert.equal(outcome.hash, hash); } });
    assert.equal(result.pending, true); waitHook = undefined;
  });
  await client.lockKeyMaterial();
});
