import { closeSync, openSync, unlinkSync, writeFileSync, fsyncSync } from 'node:fs';
import { resolve } from 'node:path';

/** One process owns the key file and all per-chain journals until it finishes. */
export async function withDemoLock<T>(root: string, run: () => Promise<T>): Promise<T> {
  const path = resolve(root, 'demo-operation.lock');
  let fd: number;
  try { fd = openSync(path, 'wx', 0o600); }
  catch { throw new Error(`The demo is locked by another process. After a crash, confirm the previous process has stopped before removing ${path}`); }
  try { writeFileSync(fd, JSON.stringify({ pid: process.pid })); return await run(); }
  finally { closeSync(fd); unlinkSync(path); }
}

export function reserveDemoIndex(localNext: number, chainNext: number, selected?: number): number {
  if (![localNext, chainNext].every(n => Number.isSafeInteger(n) && n >= 0 && n <= 65_536)) throw new Error('Invalid journal/chain index');
  const floor = Math.max(localNext, chainNext);
  const index = selected ?? floor;
  if (!Number.isSafeInteger(index) || index < floor || index >= 65_536) throw new Error('Index is used, invalid, or outside lane 0');
  return index;
}

export function broadcastAllowed(command: string, chainId: number, flags: Record<string, string | boolean>): boolean {
  const writes = ['create-vault', 'deposit', 'deploy-token', 'spend', 'replay', 'recover', 'drain'];
  if (!writes.includes(command)) return true;
  return flags.broadcast === true && (chainId !== 56 || flags['allow-mainnet'] === true);
}

export function initializeDemoJournal(path: string): void {
  let fd: number;
  try { fd = openSync(path, 'wx', 0o600); }
  catch (e) { if ((e as NodeJS.ErrnoException).code === 'EEXIST') return; throw e; }
  try { writeFileSync(fd, JSON.stringify({ nextIndex: 0, lastReservation: null })); fsyncSync(fd); }
  finally { closeSync(fd); }
}

export async function requireRejectedReplay(call: () => Promise<unknown>): Promise<unknown> {
  try { await call(); } catch (error) { return error; }
  throw new Error('Replay unexpectedly succeeded; no transaction was submitted.');
}
