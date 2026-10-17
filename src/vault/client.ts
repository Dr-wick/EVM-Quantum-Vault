// SPDX-License-Identifier: MIT
/**
 * Browser orchestration for vault operations:
 *   chain reads → digest cross-check (no leaf burned) → journal reservation
 *   (durable, before signing) → worker signing → calldata → wallet transaction.
 * The signing journal lives here (main thread, single writer); the worker only
 * does cryptography. Never auto-resends a transaction.
 */
import { bytesToHex, formatEther, type Address, type Hex, type TransactionReceipt } from 'viem';
import { cchsK, type CchsSignature, type LayerSig } from '../crypto/cchs';
import { openJournal, type JournalScope, type SigningJournal } from '../crypto/journal';
import { ensureWalletChain, getPublicClient, NETWORKS, sendTransaction, waitForReceipt } from '../services';
import { readDigestAt, readLane, readNeedsTopLayer, readVaultGlobals, readVaultKey } from './chain';
import { assertCurrentKey, assertRecoveryIntent, recoveryDigest, recoveryState, samePublicKey } from './recovery';
import * as ops from './ops';
import type { RecoveryIntent, VaultPublicKey, VaultRecord, VaultWorkerMessage, VaultWorkerRequest, VaultWorkerResponse, WireScope } from './types';

// ------------------------------------------------------------- worker bridge

let worker: Worker | undefined;
let sequence = 0;
let pending: { id: number; resolve: (r: VaultWorkerResponse) => void; reject: (e: Error) => void; onProgress?: (s: string) => void } | undefined;

function getWorker(): Worker {
  if (!worker) {
    worker = new Worker(new URL('../vault.worker.ts', import.meta.url), { type: 'module' });
    worker.onmessage = ({ data }: MessageEvent<VaultWorkerResponse>) => {
      if (!pending || pending.id !== data.id) return;
      if (data.type === 'progress') { pending.onProgress?.(data.label); return; }
      const current = pending; pending = undefined;
      if (data.type === 'error') current.reject(new Error(data.message));
      else current.resolve(data);
    };
    worker.onerror = () => {
      const current = pending; pending = undefined;
      worker?.terminate(); worker = undefined;
      current?.reject(new Error('The local cryptography worker stopped. Reload the page and import your backup again.'));
    };
  }
  return worker;
}

export function requestVault(request: VaultWorkerMessage, onProgress?: (label: string) => void): Promise<VaultWorkerResponse> {
  if (pending) return Promise.reject(new Error('A vault operation is still running. Please wait.'));
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    pending = { id, resolve, reject, onProgress };
    try { getWorker().postMessage({ ...request, id } as VaultWorkerRequest); }
    catch { pending = undefined; reject(new Error('Could not start the local cryptography worker.')); }
  });
}

/** Drop seed/key material from worker memory and free the WASM instance. */
export async function lockKeyMaterial(): Promise<void> {
  // Termination is immediate even when key generation or another request is busy.
  worker?.terminate(); worker = undefined;
  const current = pending; pending = undefined;
  current?.reject(new Error('The key is locked; the operation stopped.'));
}

// ---------------------------------------------------------- vault records

const VAULTS_KEY = 'bqv.vaults.v1';

function isRecord(value: unknown): value is VaultRecord {
  const r = value as Partial<VaultRecord> | undefined;
  return !!r && (r.chainId === 56 || r.chainId === 97)
    && typeof r.factory === 'string' && typeof r.vault === 'string'
    && typeof r.namespace === 'string' && typeof r.currentEpoch === 'string'
    && typeof r.epochs === 'object' && r.epochs !== null;
}

export function loadRecords(): VaultRecord[] {
  try {
    const raw = localStorage.getItem(VAULTS_KEY);
    const list: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(list) ? list.filter(isRecord) : [];
  } catch { return []; }
}

export function recordForChain(chainId: 56 | 97): VaultRecord | null {
  const records = loadRecords().filter((r) => r.chainId === chainId);
  return records.length ? records[records.length - 1] : null; // the most recently created/used vault
}

export function saveRecord(record: VaultRecord): void {
  const list = loadRecords().filter((r) => !(r.chainId === record.chainId && r.vault === record.vault));
  list.push(record);
  localStorage.setItem(VAULTS_KEY, JSON.stringify(list));
}

/** Stop showing this vault on this machine. Chain assets are unaffected; the backup file can re-import it. */
export function removeRecord(chainId: 56 | 97, vaultAddress: string): void {
  const list = loadRecords().filter((r) => !(r.chainId === chainId && r.vault === vaultAddress));
  localStorage.setItem(VAULTS_KEY, JSON.stringify(list));
}

function appendTx(record: VaultRecord, label: string, hash: Hex, status: 'pending' | 'success' | 'reverted' = 'pending'): void {
  const existing = record.txs.find(t => t.hash === hash);
  if (existing) existing.status = status;
  else record.txs.push({ label, hash, status });
  saveRecord(record);
}

export function explorerTx(chainId: 56 | 97, hash: string): string {
  return `${NETWORKS[chainId].explorer}/tx/${hash}`;
}

// ------------------------------------------------------------- journal

let journalPromise: Promise<SigningJournal> | undefined;

async function getJournal(): Promise<SigningJournal> {
  return (journalPromise ??= openJournal().catch((error) => { journalPromise = undefined; throw error; }));
}

export function journalScopeFor(record: VaultRecord, epoch: number): JournalScope {
  const pk = record.epochs[String(epoch)];
  if (!pk) throw new Error(`The vault record has no public key for epoch ${epoch}`);
  return { ...ops.scopeFor(record.chainId, record.factory as Address, epoch, record.namespace, BigInt(record.accountIndex)), signerId: pk.root, lane: 0 };
}

/** Only for a genuinely new key tree (fresh vault creation or a fresh epoch after recovery). */
export async function initializeJournal(record: VaultRecord, epoch: number): Promise<void> {
  const journal = await getJournal();
  await journal.initializeFresh(journalScopeFor(record, epoch), { acknowledgeNewKey: true });
}

function translateJournalError(error: unknown): Error {
  const code = (error as { code?: string }).code;
  if (code === 'MISSING') return new Error('This browser has no signing journal for this key. Signing is disabled to prevent one-time key reuse. Return to the original browser, or use Rotate key to create a fresh key.');
  if (code === 'BLOCKED') return new Error('This key is blocked because of rollback or uncertain signing history. Signing is disabled; use Rotate key.');
  if (code === 'CORRUPT') return new Error('The signing journal is corrupt. Signing is disabled; rotate the key, importing your backup first if needed.');
  if (code === 'EXHAUSTED') return new Error('This signing lane is exhausted. Use Rotate key.');
  return error instanceof Error ? error : new Error(String(error));
}

// --------------------------------------------------------------- key ops

export async function generateSeedInWorker(): Promise<string> {
  const response = await requestVault({ type: 'generate' });
  if (response.type !== 'seed') throw new Error('Unexpected worker response');
  return response.seedHex;
}

export async function importSeedToWorker(seedHex: string): Promise<void> {
  const response = await requestVault({ type: 'import', seedHex });
  if (response.type !== 'imported') throw new Error('Unexpected worker response');
}

export async function generateRecoverySeed(): Promise<string> {
  const response = await requestVault({ type: 'fresh-seed' });
  if (response.type !== 'seed') throw new Error('Unexpected worker response');
  return response.seedHex;
}

export async function keygenFor(
  chainId: 56 | 97, factory: Address, namespace: string, accountIndex: string, epoch: string,
  options?: { keepCurrent?: boolean }, onProgress?: (label: string) => void,
): Promise<VaultPublicKey> {
  const scope: WireScope = { chainId, factory, namespace, accountIndex, epoch };
  const response = await requestVault({ type: 'keygen', scope, keepCurrent: options?.keepCurrent }, onProgress);
  if (response.type !== 'keygen') throw new Error('Unexpected worker response');
  return response.publicKey;
}

export async function activateNewKey(): Promise<void> {
  await requestVault({ type: 'activate' });
}

/** Offline + on-chain CREATE2 prediction cross-checked; throws on mismatch. */
export async function previewVaultAddress(chainId: 56 | 97, factory: Address, publicKey: VaultPublicKey): Promise<Address> {
  const predicted = ops.predictVaultAddress(factory, publicKey.root, publicKey.recRoot, publicKey.pkSeed);
  const onchain = await getPublicClient(chainId).readContract({
    address: factory, abi: ops.FACTORY_ABI, functionName: 'predict',
    args: [publicKey.root, publicKey.recRoot, publicKey.pkSeed],
  }) as Address;
  if (predicted.toLowerCase() !== onchain.toLowerCase()) throw new Error('The predicted address does not match the on-chain result; operation stopped');
  return predicted;
}

export interface DeployOutcome { vault: Address; hash: Hex; pending: boolean }

export async function deployVault(options: {
  chainId: 56 | 97; factory: Address; publicKey: VaultPublicKey; fundValueWei: bigint; from: Address;
  onSubmitted: (outcome: DeployOutcome) => Promise<void>;
}): Promise<DeployOutcome> {
  const client = getPublicClient(options.chainId);
  const vault = await previewVaultAddress(options.chainId, options.factory, options.publicKey);
  const data = ops.encodeFactoryDeploy(options.publicKey.root, options.publicKey.recRoot, options.publicKey.pkSeed);
  await ensureWalletChain(options.chainId);
  const hash = await sendTransaction({ from: options.from, to: options.factory, data, value: options.fundValueWei });
  await options.onSubmitted({ vault, hash, pending: true });
  const receipt = await waitForReceipt(options.chainId, hash);
  if (!receipt) return { vault, hash, pending: true };
  if (receipt.status !== 'success') throw new Error(`Deployment transaction reverted: ${explorerTx(options.chainId, hash)}`);
  const code = await client.getCode({ address: vault });
  if (!code || code === '0x') throw new Error('No contract code exists at the deployed address; operation stopped');
  return { vault, hash, pending: false };
}

/** Rebuild a record from an imported backup's public fields (localStorage was cleared). */
export async function adoptFromBackup(chainId: 56 | 97, publicFields: ops.SeedBackupPublic, publicKey: VaultPublicKey): Promise<VaultRecord> {
  ops.validateBackupPublic(publicFields);
  if (publicFields.chainId !== undefined && publicFields.chainId !== chainId) throw new Error('The backup belongs to a different network');
  type RecordField = { factory?: string | null };
  const factory = (publicFields as RecordField).factory ?? ops.FACTORY[chainId];
  if (!factory) throw new Error('The backup has no factory address and this network has no configured factory');
  if (!publicFields.vault && publicFields.epoch !== '0') throw new Error('A rotated-key backup must include the original vault address');
  const vault = (publicFields.vault ?? ops.predictVaultAddress(factory as Address, publicKey.root, publicKey.recRoot, publicKey.pkSeed)) as Address;
  const code = await getPublicClient(chainId).getCode({ address: vault });
  if (!code || code === '0x') throw new Error('No on-chain vault matches this backup; check the network and backup file');
  const key = await readVaultKey(getPublicClient(chainId), vault);
  if (!samePublicKey(publicKey, key)) throw new Error('The backup does not contain the active vault key; import the current backup');
  const record: VaultRecord = {
    chainId, factory: factory as `0x${string}`, vault,
    namespace: publicFields.namespace, accountIndex: publicFields.accountIndex, createdAt: new Date().toISOString(),
    epochs: { [String(key.epoch)]: publicKey }, currentEpoch: String(key.epoch), txs: [],
  };
  saveRecord(record);
  return record;
}

/** Deposit = a plain transfer from the wallet to the vault address. No signature needed. */
export async function depositToVault(options: { chainId: 56 | 97; record: VaultRecord; from: Address; valueWei: bigint }): Promise<{ hash: Hex; pending: boolean }> {
  await ensureWalletChain(options.chainId);
  const hash = await sendTransaction({ from: options.from, to: options.record.vault, value: options.valueWei });
  appendTx(options.record, `Deposit ${formatEther(options.valueWei)} BNB`, hash);
  const receipt = await waitForReceipt(options.chainId, hash);
  if (receipt) appendTx(options.record, `Deposit ${formatEther(options.valueWei)} BNB`, hash, receipt.status);
  if (receipt?.status === 'reverted') throw new Error(`Deposit transaction reverted: ${explorerTx(options.chainId, hash)}`);
  return { hash, pending: !receipt };
}

// ------------------------------------------------------------ dashboard

export interface VaultDashboard {
  epoch: bigint; recNonce: bigint; laneNext: bigint; laneNonce: bigint; balance: bigint;
}

export async function readDashboard(chainId: 56 | 97, record: VaultRecord): Promise<VaultDashboard> {
  const client = getPublicClient(chainId);
  const vault = record.vault as Address;
  const [globals, lane, balance] = await Promise.all([
    readVaultGlobals(client, vault), readLane(client, vault, 0), client.getBalance({ address: vault }),
  ]);
  return { epoch: globals.epoch, recNonce: globals.recNonce, laneNext: lane.nextIdx, laneNonce: lane.nonce, balance };
}

// -------------------------------------------------------------- execute

export interface ExecuteRequest { target: Address; value: bigint; data: Hex }
export interface ExecutePreview { idx: number; method: 'execute' | 'executeFirst'; digest: Hex }

async function prepareDigest(chainId: 56 | 97, record: VaultRecord, request: ExecuteRequest) {
  const client = getPublicClient(chainId);
  const vault = record.vault as Address;
  if (record.chainId !== chainId) throw new Error('Vault network mismatch');
  if (record.pendingRecovery || record.pendingDeployment) throw new Error('Reconcile the pending vault creation or key rotation first');
  const publicKey = assertCurrentKey(record, await readVaultKey(client, vault));
  const lane = await readLane(client, vault, 0);
  const idx = Number(lane.nextIdx);
  const needsTop = await readNeedsTopLayer(client, vault, idx);
  const digest = ops.executeDigestFor(cchsK, {
    chainId, vault, laneNonce: lane.nonce, idx, target: request.target, value: request.value, data: request.data,
  });
  const onchain = await readDigestAt(client, vault, idx, request.target, request.value, request.data);
  if (bytesToHex(digest) !== onchain.toLowerCase()) {
    throw new Error('The local digest differs from the on-chain digest. Operation stopped; no signing index was consumed.');
  }
  return { idx, needsTop, digest, laneNonce: lane.nonce, chainNext: lane.nextIdx, client, vault, publicKey };
}

/** Pre-flight only — reads everything and cross-checks; consumes nothing. */
export async function previewExecute(chainId: 56 | 97, record: VaultRecord, request: ExecuteRequest): Promise<ExecutePreview> {
  const prepared = await prepareDigest(chainId, record, request);
  return { idx: prepared.idx, method: prepared.needsTop ? 'executeFirst' : 'execute', digest: bytesToHex(prepared.digest) as Hex };
}

export interface ExecuteOutcome { idx: number; hash: Hex; explorer: string; pending: boolean }

export async function executeVault(options: {
  chainId: 56 | 97; record: VaultRecord; request: ExecuteRequest; from: Address; onProgress?: (label: string) => void;
}): Promise<ExecuteOutcome> {
  const { chainId, record, request, from, onProgress } = options;
  let prepared = await prepareDigest(chainId, record, request);

  // Durable reservation BEFORE signing. If it returns a different index than the
  // pre-checked candidate (another tab got there first), re-derive and re-check.
  const journal = await getJournal();
  let reserved;
  try {
    reserved = await journal.reserve(journalScopeFor(record, Number(record.currentEpoch)), Number(prepared.chainNext));
  } catch (error) {
    throw translateJournalError(error);
  }
  if (reserved.index !== prepared.idx) {
    const lane = await readLane(prepared.client, prepared.vault, 0);
    const needsTop = await readNeedsTopLayer(prepared.client, prepared.vault, reserved.index);
    const digest = ops.executeDigestFor(cchsK, {
      chainId, vault: prepared.vault, laneNonce: lane.nonce, idx: reserved.index,
      target: request.target, value: request.value, data: request.data,
    });
    const onchain = await readDigestAt(prepared.client, prepared.vault, reserved.index, request.target, request.value, request.data);
    if (bytesToHex(digest) !== onchain.toLowerCase()) throw new Error('The digests still differ after reconciliation. Operation stopped; this signing index is permanently consumed.');
    prepared = { ...prepared, idx: reserved.index, needsTop, digest };
  }

  onProgress?.('Signing index reserved; generating signature…');
  assertCurrentKey(record, await readVaultKey(prepared.client, prepared.vault));
  const signed = await requestVault({ type: 'sign', expectedRoot: prepared.publicKey.root, idx: prepared.idx, digestHex: bytesToHex(prepared.digest) as Hex, needsTop: prepared.needsTop }, onProgress);
  if (signed.type !== 'signed') throw new Error('Unexpected signing worker response');
  const signature: CchsSignature = {
    l0: signed.l0 as LayerSig,
    ...(signed.l1 ? { l1: signed.l1 as LayerSig } : {}),
    idx: prepared.idx,
  };
  const calldata = ops.encodeExecuteCall(prepared.idx, request.target, request.value, request.data, signature);

  await ensureWalletChain(chainId);
  try {
    const gas = await prepared.client.estimateGas({ account: from, to: prepared.vault, data: calldata });
    onProgress?.(`Contract simulation passed (estimated gas ${gas}). Confirm in your wallet…`);
  } catch (error) {
    const name = ops.vaultErrorName(error);
    throw new Error(`Contract simulation failed${name ? ` (${name})` : ''}; nothing was sent. This signing index is consumed; the next attempt will use a new one.`);
  }
  const hash = await sendTransaction({ from, to: prepared.vault, data: calldata });
  appendTx(record, `exec ${prepared.needsTop ? 'executeFirst' : 'execute'}@${prepared.idx}`, hash);
  const receipt = await waitForReceipt(chainId, hash);
  if (!receipt) return { idx: prepared.idx, hash, explorer: explorerTx(chainId, hash), pending: true };
  if (receipt.status !== 'success') throw new Error(`Transaction reverted: ${explorerTx(chainId, hash)}. This signing index is consumed; the next attempt will use a new one.`);
  appendTx(record, `exec ${prepared.needsTop ? 'executeFirst' : 'execute'}@${prepared.idx}`, hash, 'success');
  return { idx: prepared.idx, hash, explorer: explorerTx(chainId, hash), pending: false };
}

// --------------------------------------------------------------- recover

export interface RecoverOutcome { newEpoch: number; hash: Hex; explorer: string; pending: boolean }

/** Prepare once. The caller must save/confirm the new seed before submitting. */
export async function prepareRecovery(record: VaultRecord, seedHex: Hex, onProgress?: (label: string) => void): Promise<RecoveryIntent> {
  if (record.pendingRecovery) throw new Error('A recovery intent is already fixed. Continue that intent; do not generate another key.');
  const state = await readVaultKey(getPublicClient(record.chainId), record.vault);
  const old = assertCurrentKey(record, state);
  if (state.recNonce >= 256n) throw new Error('The recovery capacity of this vault is exhausted');
  const newEpoch = String(state.epoch + 1n);
  const response = await requestVault({ type: 'stage-recovery', expectedRoot: old.root, seedHex,
    scope: { chainId: record.chainId, factory: record.factory, namespace: record.namespace, accountIndex: record.accountIndex, epoch: newEpoch } }, onProgress);
  if (response.type !== 'keygen') throw new Error('Unexpected recovery worker response');
  const intent: RecoveryIntent = { oldEpoch: String(state.epoch), oldRoot: old.root, recNonce: String(state.recNonce),
    newEpoch, newPublicKey: response.publicKey, replacesSeed: true, digest: '0x' };
  intent.digest = recoveryDigest(record, intent);
  return intent;
}

/** Commit only after the new backup has been saved and checked by its owner. */
export async function saveRecovery(record: VaultRecord, intent: RecoveryIntent): Promise<void> {
  assertRecoveryIntent(record, intent);
  const state = await readVaultKey(getPublicClient(record.chainId), record.vault);
  assertCurrentKey(record, state);
  if (String(state.recNonce) !== intent.recNonce) throw new Error('The recovery counter changed; reconcile the state again');
  if (record.pendingRecovery && record.pendingRecovery.digest !== intent.digest) throw new Error('Another recovery intent already exists');
  const journal = await getJournal();
  // A missing spending journal never gets recreated. Recovery has its own binding.
  await journal.bindRecovery(journalScopeFor(record, Number(state.epoch)), Number(state.recNonce), intent.digest);
  record.pendingRecovery = intent;
  record.epochs[intent.newEpoch] = intent.newPublicKey;
  saveRecord(record); // only public data; survive reload before any signature
  try { await initializeJournal(record, Number(intent.newEpoch)); }
  catch (e) { if ((e as { code?: string }).code !== 'EXISTS') throw e; }
}

/** Read-only on chain; completes public local state without recreating journals. */
export async function reconcileRecovery(record: VaultRecord): Promise<boolean> {
  const intent = record.pendingRecovery;
  if (!intent) return false;
  const state = await readVaultKey(getPublicClient(record.chainId), record.vault);
  if (recoveryState(record, state) !== 'confirmed') return false;
  record.epochs[intent.newEpoch] = intent.newPublicKey;
  record.currentEpoch = intent.newEpoch;
  if (intent.hash) appendTx(record, `recover -> epoch ${intent.newEpoch}`, intent.hash, 'success');
  delete record.pendingRecovery;
  saveRecord(record);
  await lockKeyMaterial(); // after reload the pending worker may no longer exist
  return true;
}

/** Recover a lost wallet response using a user-supplied, exactly matching transaction. */
export async function attachRecoveryTransaction(record: VaultRecord, hash: Hex): Promise<void> {
  const intent = record.pendingRecovery;
  if (!intent?.calldata || !/^0x[0-9a-f]{64}$/i.test(hash)) throw new Error('Enter the complete hash of this recovery transaction from your wallet');
  assertRecoveryIntent(record, intent);
  const tx = await getPublicClient(record.chainId).getTransaction({ hash });
  if (tx.to?.toLowerCase() !== record.vault.toLowerCase() || tx.input.toLowerCase() !== intent.calldata.toLowerCase() || tx.value !== 0n) {
    throw new Error('The transaction does not match this recovery intent; the recovery record was not changed');
  }
  intent.hash = hash; intent.submissionUncertain = false; saveRecord(record);
}

export async function recoverVault(options: {
  chainId: 56 | 97; record: VaultRecord; from: Address; onProgress?: (label: string) => void;
}): Promise<RecoverOutcome> {
  const { chainId, record, from, onProgress } = options;
  if (chainId !== record.chainId) throw new Error('Vault network mismatch');
  const client = getPublicClient(chainId);
  const vault = record.vault as Address;
  const intent = record.pendingRecovery;
  if (!intent) throw new Error('Generate, download, and confirm the new backup first');
  assertRecoveryIntent(record, intent);
  const outcome = (pending: boolean): RecoverOutcome => ({ newEpoch: Number(intent.newEpoch), hash: intent.hash!, explorer: intent.hash ? explorerTx(chainId, intent.hash) : '', pending });
  if (await reconcileRecovery(record)) return outcome(false);
  if (intent.hash) {
    const receipt = await receiptNow(chainId, intent.hash);
    if (!receipt || receipt.status === 'success') return outcome(true); // wait, never resend an unknown transaction
    appendTx(record, `recover -> epoch ${intent.newEpoch}`, intent.hash, 'reverted');
    delete intent.hash; intent.submissionUncertain = false; saveRecord(record);
  }
  if (intent.submissionUncertain) throw new Error('The previous submission is uncertain; resubmission is blocked. Check your wallet history and refresh the on-chain state.');
  const state = await readVaultKey(client, vault);
  assertCurrentKey(record, state);
  if (String(state.recNonce) !== intent.recNonce) throw new Error('The recovery counter changed; operation stopped');
  await (await getJournal()).bindRecovery(journalScopeFor(record, Number(intent.oldEpoch)), Number(state.recNonce), intent.digest);
  if (!intent.calldata) {
    const signed = await requestVault({ type: 'recover-sign', expectedRoot: intent.oldRoot, recNonce: intent.recNonce, digestHex: intent.digest }, onProgress);
    if (signed.type !== 'recover-signed') throw new Error('Unexpected recovery signing worker response');
    intent.calldata = ops.encodeRecoverCall(intent.newPublicKey.root, intent.newPublicKey.recRoot, intent.newPublicKey.pkSeed, { wots: signed.wots, auth: signed.auth });
    saveRecord(record); // persist the identical signed payload before opening the wallet
  }
  await ensureWalletChain(chainId);
  try {
    const gas = await client.estimateGas({ account: from, to: vault, data: intent.calldata });
    onProgress?.(`Contract simulation passed (estimated gas ${gas}). Confirm in your wallet…`);
  } catch (error) {
    const name = ops.vaultErrorName(error);
    throw new Error(`Key rotation simulation failed${name ? ` (${name})` : ''}; nothing was sent.`);
  }
  intent.submissionUncertain = true; saveRecord(record);
  try { intent.hash = await sendTransaction({ from, to: vault, data: intent.calldata }); }
  catch (e) {
    if ((e as { code?: number }).code === 4001) { intent.submissionUncertain = false; saveRecord(record); }
    throw e;
  }
  intent.submissionUncertain = false;
  appendTx(record, `recover -> epoch ${intent.newEpoch}`, intent.hash);
  const receipt = await waitForReceipt(chainId, intent.hash);
  if (receipt?.status === 'reverted') {
    appendTx(record, `recover -> epoch ${intent.newEpoch}`, intent.hash, 'reverted');
    throw new Error(`Key rotation reverted; continue the same recovery intent: ${explorerTx(chainId, intent.hash)}`);
  }
  return outcome(!(await reconcileRecovery(record)));
}

/** Verify a receipt exists later (manual refresh helper for pending outcomes). */
export async function receiptNow(chainId: 56 | 97, hash: Hex): Promise<TransactionReceipt | null> {
  return await getPublicClient(chainId).getTransactionReceipt({ hash }).catch(() => null);
}

export async function reconcileTransactions(record: VaultRecord): Promise<void> {
  const statuses = await Promise.all(record.txs.filter(tx => tx.status === 'pending').map(async tx => {
    const receipt = await receiptNow(record.chainId, tx.hash);
    return receipt ? { hash: tx.hash, status: receipt.status } : null;
  }));
  // A read started before another tab's recovery must not overwrite its intent.
  const latest = loadRecords().find(r => r.chainId === record.chainId && r.vault.toLowerCase() === record.vault.toLowerCase());
  if (latest) {
    Object.assign(record, latest);
    record.pendingRecovery = latest.pendingRecovery;
    record.pendingDeployment = latest.pendingDeployment;
  }
  for (const update of statuses) {
    if (update) for (const tx of record.txs.filter(t => t.hash === update.hash)) tx.status = update.status;
  }
  saveRecord(record);
}
