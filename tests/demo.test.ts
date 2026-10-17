import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { broadcastAllowed, reserveDemoIndex, withDemoLock, initializeDemoJournal, requireRejectedReplay } from '../scripts/demo-storage';

test('CLI reserves the exact selected leaf, rejects reuse and invalid values', () => {
  const chosen = reserveDemoIndex(3, 2, 100);
  assert.equal(chosen, 100);
  assert.equal(reserveDemoIndex(chosen + 1, 2), 101);
  for (const value of [100, -1, 1.5, NaN, Infinity, 65_536]) assert.throws(() => reserveDemoIndex(101, 2, value));
});

test('replay success stops the command; a new journal never resets an existing reservation', async () => {
  await assert.rejects(requireRejectedReplay(async () => 'success'), /unexpectedly succeeded/);
  const error = new Error('reverted');
  assert.equal(await requireRejectedReplay(async () => { throw error; }), error);
  const dir = mkdtempSync(join(tmpdir(), 'bqv-journal-'));
  try {
    const old = join(dir, 'old.local'), fresh = join(dir, 'new.local');
    writeFileSync(old, JSON.stringify({ nextIndex: 65536 }));
    initializeDemoJournal(fresh);
    assert.equal(reserveDemoIndex(JSON.parse(readFileSync(fresh, 'utf8')).nextIndex, 0), 0);
    writeFileSync(fresh, JSON.stringify({ nextIndex: 2 }));
    initializeDemoJournal(fresh);
    assert.equal(JSON.parse(readFileSync(fresh, 'utf8')).nextIndex, 2);
  } finally { assert.ok(resolve(dir).startsWith(resolve(tmpdir()))); rmSync(dir, { recursive: true }); }
});

test('CLI lock rejects a concurrent writer and releases after a failed operation', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'bqv-lock-'));
  try {
    await withDemoLock(dir, async () => { await assert.rejects(withDemoLock(dir, async () => {}), /locked/); });
    await assert.rejects(withDemoLock(dir, async () => { throw new Error('failure'); }), /failure/);
    await withDemoLock(dir, async () => {});
  } finally { rmSync(dir, { recursive: true }); }
});

test('every CLI write, including an empty-vault drain, is gated before any side effect', () => {
  for (const command of ['create-vault', 'deposit', 'deploy-token', 'spend', 'replay', 'recover', 'drain']) {
    assert.equal(broadcastAllowed(command, 56, {}), false);
    assert.equal(broadcastAllowed(command, 56, { broadcast: true }), false);
    assert.equal(broadcastAllowed(command, 56, { broadcast: true, 'allow-mainnet': true }), true);
    assert.equal(broadcastAllowed(command, 97, { broadcast: true }), true);
  }
  // Actual CLI entrypoint: an invalid RPC and absent authorization still exit in dry run.
  for (const args of [['drain', '--chain', '56'], ['recover', '--chain', '56', '--broadcast'], ['spend', '--chain', '97']]) {
    const out = execFileSync(process.execPath, ['--import', 'tsx', resolve('scripts/demo.ts'), ...args], {
      cwd: process.cwd(), encoding: 'utf8', env: { ...process.env, RPC_URL: 'http://127.0.0.1:1', TSX_DISABLE_CACHE: '1' },
    });
    assert.match(out, /Dry run/);
  }
});
