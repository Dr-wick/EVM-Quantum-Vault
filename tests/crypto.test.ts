import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { IDBFactory } from 'fake-indexeddb';
import { cchsK, eq, sk, toHex, type Tree, type LayerSig } from '../src/crypto/cchs';
import { deriveAccountKey, accountScopeId, type AccountKeyScope } from '../src/crypto/derive';
import { fastCchs } from '../src/crypto/fast';
import { openJournal, JournalError, type JournalScope } from '../src/crypto/journal';

Object.defineProperty(globalThis, 'indexedDB', { configurable: true, writable: true, value: new IDBFactory() });
const context: AccountKeyScope = {
  chainId: 97, factory: '0x00000000000000000000000000000000000000ab',
  deploymentNamespace: 'test-only-deployment', accountIndex: 0n, epoch: 0n,
};
const scope: JournalScope = { ...context, signerId: `0x${'12'.repeat(32)}`, lane: 0 };
const seed = new Uint8Array(32).fill(9); // public synthetic test data
const errorCode = (code: string) => (error: unknown) => error instanceof JournalError && error.code === code;
const databaseName = () => `bqv-test-${crypto.randomUUID()}`;

test('KDF separates chain, deployment, factory, account, epoch, spending and recovery', () => {
  const first = deriveAccountKey(seed, context);
  assert.ok(eq(first.master, deriveAccountKey(seed, context).master));
  assert.ok(!eq(first.master, first.recoveryMaster!));
  const alternatives: AccountKeyScope[] = [
    { ...context, chainId: 56 }, { ...context, factory: '0x00000000000000000000000000000000000000ac' },
    { ...context, deploymentNamespace: 'another-deployment' }, { ...context, accountIndex: 1n }, { ...context, epoch: 1n },
  ];
  const secrets = new Set([toHex(first.master), toHex(first.recoveryMaster!)]);
  for (const other of alternatives) {
    const key = deriveAccountKey(seed, other);
    for (const part of [key.master, key.recoveryMaster!]) { assert.ok(!secrets.has(toHex(part))); secrets.add(toHex(part)); }
  }
  assert.ok(eq(first.master, deriveAccountKey(seed, { ...context, factory: context.factory.toUpperCase().replace('0X', '0x') as `0x${string}` }).master));
  assert.ok(!eq(sk(first, 0, 0n, 0, 0), sk(first, 0xff, 0n, 0, 0)));
  assert.throws(() => deriveAccountKey(seed, { ...context, chainId: 1 as 56 }), /only BSC/);
  assert.throws(() => deriveAccountKey(seed, { ...context, accountIndex: -1n }), /unsigned/);
  assert.throws(() => deriveAccountKey(seed, { ...context, epoch: 1n << 64n }), /unsigned/);
  assert.throws(() => deriveAccountKey(seed, { ...context, deploymentNamespace: '' }), /namespace/);
  assert.throws(() => deriveAccountKey(new Uint8Array(12), context), /32 or 64/);
  assert.notEqual(accountScopeId(context), accountScopeId(alternatives[2]));
});

test('Keccak WASM and JS signatures verify with public vector; changed message/signature fail', async () => {
  const f = JSON.parse(readFileSync(new URL('../src/crypto/fixtures/public-k20.json', import.meta.url), 'utf8'));
  const bytes = (hex: string) => new Uint8Array(Buffer.from(hex.slice(2), 'hex'));
  const key = { master: bytes(f.master) };
  const pub = { root: bytes(f.root), recRoot: bytes(f.recRoot), seed: bytes(f.seed) };
  const bottomRoot = bytes(f.bottomRoot0);
  const bottom: Tree = { height: 10, root: bottomRoot, levels: [...f.auth.map((h: string) => [new Uint8Array(32), bytes(h)]), [bottomRoot]] };
  const trees = new Map([['0/0', bottom]]);
  const top: LayerSig = { wots: f.top.wots.map(bytes), auth: f.top.auth.map(bytes) };
  const payload = { chainId: 97n, account: new Uint8Array(20).fill(3), nonce: 0n, idx: 0n, target: new Uint8Array(20).fill(4), value: 123n, dataHash: cchsK.hash(new Uint8Array()) };
  const digest = cchsK.executeDigest(payload);
  const wasm = await fastCchs();
  assert.ok(eq(digest, wasm.executeDigest(payload)));
  const a = { ...cchsK.sign(key, 0, digest, true, trees), l1: top };
  const b = { ...wasm.sign(key, 0, digest, true, trees), l1: top };
  assert.deepEqual(a, b);
  assert.ok(eq(cchsK.verify(pub, 0, digest, a), bottomRoot));
  assert.ok(eq(wasm.verify(pub, 0, digest, b), bottomRoot));
  const changed = cchsK.executeDigest({ ...payload, value: 124n });
  assert.throws(() => cchsK.verify(pub, 0, changed, a));
  const tampered = structuredClone(a); tampered.l0.wots[0][0] ^= 1;
  assert.throws(() => cchsK.verify(pub, 0, digest, tampered));
  assert.throws(() => cchsK.executeDigest({ ...payload, chainId: 1n }), /only BSC/);
  assert.throws(() => cchsK.executeDigest({ ...payload, value: -1n }), /out of range/);
  assert.throws(() => cchsK.verify(pub, 0, digest, { ...a, l0: { ...a.l0, auth: [] } }), /shape/);
  assert.throws(() => cchsK.sign(key, -1, digest, true, trees), /index/);
  // No two-message signing under one leaf is done here: both backends receive
  // the identical digest, using a publicly known fixture key.
});

test('two IndexedDB connections atomically reserve unique leaves for concurrent callers', async () => {
  const name = databaseName();
  const [a, b] = await Promise.all([openJournal(name), openJournal(name)]);
  try {
    await a.initializeFresh(scope, { acknowledgeNewKey: true });
    const reservations = await Promise.all(Array.from({ length: 40 }, (_, i) => (i % 2 ? a : b).reserve(scope)));
    assert.deepEqual(reservations.map(x => x.index).sort((x, y) => x - y), Array.from({ length: 40 }, (_, i) => i));
    assert.equal(new Set(reservations.map(x => x.reservationId)).size, 40);
    assert.equal((await a.reserve(scope)).index, 40);
    await assert.rejects(a.initializeFresh(scope, { acknowledgeNewKey: true }), errorCode('EXISTS'));
  } finally { a.close(); b.close(); }
});

test('missing journal refuses even a zero chain counter and a different signer', async () => {
  const journal = await openJournal(databaseName());
  try {
    await assert.rejects(journal.reserve(scope, 0n), errorCode('MISSING'));
    await assert.rejects(journal.initializeFresh(scope, { acknowledgeNewKey: false } as never), errorCode('MISSING'));
    await journal.initializeFresh(scope, { acknowledgeNewKey: true });
    await assert.rejects(journal.reserve({ ...scope, signerId: `0x${'13'.repeat(32)}` }, 0n), errorCode('MISSING'));
    assert.equal((await journal.reserve(scope, 8n)).index, 8);
    assert.equal((await journal.reserve(scope, 0n)).index, 9);
  } finally { journal.close(); }
});

async function mutateJournal(name: string, mutate: (row: any) => any): Promise<void> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => { const r = indexedDB.open(name, 1); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction('journals', 'readwrite');
    const cursor = tx.objectStore('journals').openCursor();
    cursor.onsuccess = () => { const c = cursor.result; assert.ok(c); c.update(mutate(c.value)); };
    tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
  });
  db.close();
}

test('corrupt journal or mismatched history fails closed without resetting its counter', async () => {
  const name = databaseName(), journal = await openJournal(name);
  try {
    await journal.initializeFresh(scope, { acknowledgeNewKey: true });
    await journal.reserve(scope);
    await mutateJournal(name, row => ({ ...row, nextIndex: 3 }));
    await assert.rejects(journal.reserve(scope), errorCode('CORRUPT'));
    await mutateJournal(name, row => ({ ...row, nextIndex: Number.NaN }));
    await assert.rejects(journal.reserve(scope), errorCode('CORRUPT'));
  } finally { journal.close(); }
});

test('known backup restore blocks signing; initialization cannot clear the block', async () => {
  const journal = await openJournal(databaseName());
  try {
    await journal.initializeFresh(scope, { acknowledgeNewKey: true });
    await journal.reserve(scope);
    await journal.invalidate(scope, 'Known profile rollback; this key must no longer sign.');
    await assert.rejects(journal.reserve(scope), errorCode('BLOCKED'));
    await assert.rejects(journal.initializeFresh(scope, { acknowledgeNewKey: true }), errorCode('EXISTS'));
  } finally { journal.close(); }
});

test('IndexedDB unavailable never falls back to localStorage or process memory', async () => {
  const saved = globalThis.indexedDB;
  Object.defineProperty(globalThis, 'indexedDB', { configurable: true, writable: true, value: undefined });
  try { await assert.rejects(openJournal(databaseName()), errorCode('UNAVAILABLE')); }
  finally { Object.defineProperty(globalThis, 'indexedDB', { configurable: true, writable: true, value: saved }); }
});

test('recovery binding permits identical retries and atomically rejects another digest', async () => {
  const name = databaseName();
  const [a, b] = await Promise.all([openJournal(name), openJournal(name)]);
  try {
    const digest = `0x${'aa'.repeat(32)}`, other = `0x${'bb'.repeat(32)}`;
    const results = await Promise.allSettled([a.bindRecovery(scope, 0, digest), b.bindRecovery(scope, 0, other)]);
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    const winner = results[0].status === 'fulfilled' ? digest : other;
    await a.bindRecovery(scope, 0, winner);
    await assert.rejects(b.bindRecovery(scope, 0, winner === digest ? other : digest), errorCode('BLOCKED'));
    await assert.rejects(a.bindRecovery(scope, 256, digest), errorCode('CORRUPT'));
    await assert.rejects(a.bindRecovery(scope, -1, digest), errorCode('CORRUPT'));
  } finally { a.close(); b.close(); }
});
