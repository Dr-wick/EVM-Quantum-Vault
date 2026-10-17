// SPDX-License-Identifier: MIT
import { accountScopeId, type AccountKeyScope } from './derive';

/**
 * The signerId is the public spending root, normalized 32-byte hex. All tabs
 * using the same key MUST share this exact scope and database name.
 * A lane is a 65,536-leaf partition; this journal is not a device enrollment
 * protocol. Multiple devices must not share a lane.
 */
export interface JournalScope extends AccountKeyScope {
  signerId: `0x${string}`;
  lane: number;
}
export interface Reservation { index: number; reservationId: string; }
export type JournalErrorCode = 'UNAVAILABLE' | 'MISSING' | 'CORRUPT' | 'EXISTS' | 'BLOCKED' | 'EXHAUSTED';
export class JournalError extends Error {
  constructor(readonly code: JournalErrorCode, message: string) { super(message); this.name = 'JournalError'; }
}

interface JournalRow {
  version: 1;
  scope: string;
  status: 'active' | 'blocked';
  nextIndex: number;
  lastReservation: string | null;
  reason?: string;
}
interface ReservationRow extends Reservation { scope: string; }
const LANE_SIZE = 65_536;
const DEFAULT_DATABASE = 'bsc-quantum-vault/signing-journal/v1';

function scopeId(scope: JournalScope): string {
  if (!/^0x[0-9a-fA-F]{64}$/.test(scope.signerId)) throw new JournalError('CORRUPT', 'signerId must be a 32-byte public root');
  if (!Number.isInteger(scope.lane) || scope.lane < 0 || scope.lane >= 16) throw new JournalError('CORRUPT', 'lane must be an integer from 0 to 15');
  return JSON.stringify([accountScopeId(scope), scope.signerId.toLowerCase(), scope.lane]);
}
function validRow(value: unknown, id: string, first: number, end: number): JournalRow {
  const row = value as JournalRow | undefined;
  if (row === undefined) throw new JournalError('MISSING', 'Signing journal is missing. Do not reconstruct it from the chain counter or an old backup; use a genuinely new key/epoch.');
  if (!row || row.version !== 1 || row.scope !== id || !['active', 'blocked'].includes(row.status) || !Number.isSafeInteger(row.nextIndex) || row.nextIndex < first || row.nextIndex > end || !(row.lastReservation === null || typeof row.lastReservation === 'string') || (row.nextIndex > first && !row.lastReservation)) throw new JournalError('CORRUPT', 'Signing journal is invalid; signing is disabled.');
  if (row.status === 'blocked') throw new JournalError('BLOCKED', row.reason ?? 'Signing journal is blocked.');
  return row;
}

/**
 * IndexedDB readwrite transactions serialize across tabs. A reservation is
 * returned only after transaction completion, so callers cannot sign before
 * the allocation is durable. There is deliberately no localStorage/memory
 * fallback and no restore/import API.
 *
 * Local storage cannot detect rollback of an entire valid database. After a
 * known restore, cloned profile, or uncertain history, call invalidate and
 * stop using the key. This API does not claim hardware anti-rollback or safe
 * recovery of a funded account. The lab always starts with a fresh random key.
 */
export class SigningJournal {
  constructor(private readonly db: IDBDatabase) {}

  /** One recovery leaf may retry one identical intent, never authorize another target. */
  bindRecovery(scope: JournalScope, nonce: number, digest: string): Promise<void> {
    if (!Number.isInteger(nonce) || nonce < 0 || nonce >= 256 || !/^0x[0-9a-f]{64}$/i.test(digest)) {
      return Promise.reject(new JournalError('CORRUPT', 'Invalid recovery authorization.'));
    }
    const id = `recovery:${scopeId(scope)}:${nonce}`;
    return this.transact<void>((tx, setResult, fail) => {
      const store = tx.objectStore('reservations');
      const req = store.get(id);
      req.onsuccess = () => {
        if (req.result !== undefined && req.result.digest !== digest.toLowerCase()) {
          fail(new JournalError('BLOCKED', 'This recovery authorization is already bound to a different new key. Continue with the original new backup; signing another intent is prohibited.'));
          return;
        }
        if (req.result === undefined) store.add({ digest: digest.toLowerCase() }, id);
        setResult(undefined);
      };
    });
  }

  /** Only for a genuinely NEW key, never to repair a missing record for an old key. */
  initializeFresh(scope: JournalScope, options: { acknowledgeNewKey: true }): Promise<void> {
    if (options?.acknowledgeNewKey !== true) return Promise.reject(new JournalError('MISSING', 'Explicit new-key initialization is required.'));
    const id = scopeId(scope);
    return this.transact<void>((tx, setResult, fail) => {
      const store = tx.objectStore('journals');
      const req = store.get(id);
      req.onsuccess = () => {
        if (req.result !== undefined) { fail(new JournalError('EXISTS', 'Journal already exists; it cannot be reset.')); return; }
        store.add({ version: 1, scope: id, status: 'active', nextIndex: scope.lane * LANE_SIZE, lastReservation: null } satisfies JournalRow, id);
        setResult(undefined);
      };
    });
  }

  /** Consume an index permanently, even if signing or submission later fails. */
  reserve(scope: JournalScope, onchainNext: number | bigint = scope.lane * LANE_SIZE): Promise<Reservation> {
    const id = scopeId(scope), first = scope.lane * LANE_SIZE, end = first + LANE_SIZE;
    const chain = Number(onchainNext);
    if (!Number.isSafeInteger(chain) || chain < first || chain > end) return Promise.reject(new JournalError('CORRUPT', 'Chain counter is outside the selected lane.'));
    return this.transact<Reservation>((tx, setResult, fail) => {
      const store = tx.objectStore('journals');
      const req = store.get(id);
      req.onsuccess = () => {
        try {
          const row = validRow(req.result, id, first, end);
          const allocate = () => {
            try {
              const index = Math.max(row.nextIndex, chain);
              if (index >= end) throw new JournalError('EXHAUSTED', 'This signing lane is exhausted.');
              const reservationId = globalThis.crypto.randomUUID();
              const reservation: ReservationRow = { scope: id, index, reservationId };
              tx.objectStore('reservations').add(reservation, reservationId);
              store.put({ ...row, nextIndex: index + 1, lastReservation: reservationId } satisfies JournalRow, id);
              setResult({ index, reservationId });
            } catch (error) { fail(error); }
          };
          if (row.lastReservation) {
            const previous = tx.objectStore('reservations').get(row.lastReservation);
            previous.onsuccess = () => {
              const p = previous.result as ReservationRow | undefined;
              if (!p || p.scope !== id || p.reservationId !== row.lastReservation || p.index !== row.nextIndex - 1) { fail(new JournalError('CORRUPT', 'Journal counter does not match its reservation history.')); return; }
              allocate();
            };
          } else allocate();
        } catch (error) { fail(error); }
      };
    });
  }

  /** Permanently block a key after a known restore or uncertain signing history. */
  invalidate(scope: JournalScope, reason: string): Promise<void> {
    const id = scopeId(scope);
    return this.transact<void>((tx, setResult) => {
      tx.objectStore('journals').put({ version: 1, scope: id, status: 'blocked', nextIndex: scope.lane * LANE_SIZE, lastReservation: null, reason: reason || 'Uncertain signing history.' } satisfies JournalRow, id);
      setResult(undefined);
    });
  }

  close(): void { this.db.close(); }

  private transact<T>(run: (tx: IDBTransaction, setResult: (result: T) => void, fail: (error: unknown) => void) => void): Promise<T> {
    return new Promise((resolve, reject) => {
      let failure: unknown;
      let result: T;
      let tx: IDBTransaction;
      try {
        tx = this.db.transaction(['journals', 'reservations'], 'readwrite', { durability: 'strict' });
      } catch (error) { reject(new JournalError('UNAVAILABLE', `Durable IndexedDB transaction unavailable: ${String(error)}`)); return; }
      const fail = (error: unknown) => { failure = error; try { tx.abort(); } catch { /* already aborted */ } };
      tx.oncomplete = () => resolve(result);
      tx.onabort = () => reject(failure ?? tx.error ?? new JournalError('UNAVAILABLE', 'Signing journal transaction aborted.'));
      tx.onerror = () => { failure ??= tx.error ?? new JournalError('UNAVAILABLE', 'Signing journal write failed.'); };
      try { run(tx, value => { result = value; }, fail); } catch (error) { fail(error); }
    });
  }
}

export function openJournal(dbName = DEFAULT_DATABASE): Promise<SigningJournal> {
  return new Promise((resolve, reject) => {
    if (!globalThis.indexedDB) { reject(new JournalError('UNAVAILABLE', 'IndexedDB is required for signing; no fallback is permitted.')); return; }
    const req = globalThis.indexedDB.open(dbName, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore('journals');
      req.result.createObjectStore('reservations');
    };
    req.onerror = () => reject(new JournalError('UNAVAILABLE', `Cannot open signing journal: ${req.error?.message ?? 'unknown error'}`));
    req.onblocked = () => reject(new JournalError('UNAVAILABLE', 'Signing journal upgrade is blocked by another tab.'));
    req.onsuccess = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('journals') || !db.objectStoreNames.contains('reservations')) { db.close(); reject(new JournalError('CORRUPT', 'Signing journal stores are missing.')); return; }
      db.onversionchange = () => db.close();
      resolve(new SigningJournal(db));
    };
  });
}
