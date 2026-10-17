/**
 * EVM Quantum Vault — demo console (local tooling, never bundled into the app).
 *
 * Drives a deployed factory/vault through the full lifecycle on BSC:
 *   keygen -> create vault -> deposit -> signed spend -> replay rejection
 *   -> key rotation (recover) -> drain everything back out.
 *
 * The browser client and this console use the same encoding and digest helpers
 * from src/vault/ops.ts.
 *
 * This file is not bundled into the web application. See SECURITY.md for the
 * limitations of this unaudited prototype. The default is BSC testnet (97).
 * Chain 56 additionally requires --allow-mainnet.
 *
 * Usage: npx tsx scripts/demo.ts <command> [flags]
 *   init            generate a fresh deployer wallet + quantum master seed
 *   status          read-only: state, balances, lane counters
 *   create-vault    keygen + deploy the vault (and optionally fund via msg.value)
 *   deposit         move tBNB from the deployer wallet into the vault
 *   deploy-token    deploy the tiny demo ERC-20 and mint to the vault
 *   spend           sign (journal-first) and send one vault execution
 *   replay          resend the last spend calldata; expect a revert
 *   recover         rotate to the next epoch's key using the recovery tree
 *   drain           move all vault holdings (BNB + demo token) to an address
 *
 * Common flags: --chain 97|56   --broadcast (required for every write)
 */
import {
  createPublicClient, createWalletClient, encodeFunctionData, http, formatEther, parseEther,
  type Address, type Hex,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { bsc, bscTestnet } from 'viem/chains';
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { signatureBytes, toHex, type CchsKey, type Tree } from '../src/crypto/cchs.ts';
import { deriveAccountKey } from '../src/crypto/derive.ts';
import { fastCchs } from '../src/crypto/fast.ts';
import {
  ARTIFACTS, encodeExecuteCall, encodeFactoryDeploy, encodeRecoverCall,
  executeDigestFor, predictVaultAddress, recoveryDigestFor, scopeFor, vaultErrorName, parseSeedBackup, seedBackupFile,
  type ChainId,
} from '../src/vault/ops.ts';
import { readDigestAt, readLane, readNeedsTopLayer, readVaultGlobals, readVaultKey } from '../src/vault/chain.ts';
import { withDemoLock, reserveDemoIndex, broadcastAllowed, initializeDemoJournal, requireRejectedReplay } from './demo-storage.ts';
import { recoveryState, verifyRecoveryBackup } from '../src/vault/recovery.ts';
import type { RecoveryIntent, VaultRecord } from '../src/vault/types.ts';

const require = createRequire(import.meta.url);
const solc = require('solc') as { compile(input: string): string };

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const NAMESPACE = 'bqv-demo/v1';
const LANE_SIZE = 65_536n;

if (ARTIFACTS.format !== 'bqv-artifact-v1') throw new Error('Unrecognized artifact; run npm run compile.');
const FABI = ARTIFACTS.factory.abi;
const VABI = ARTIFACTS.vault.abi;
const KEYS_PATH = resolve(ROOT, 'demo-keys.local');

// ---------------------------------------------------------------- cli utils

function usage(): never {
  const text = readFileSync(new URL(import.meta.url), 'utf8');
  const help = text.split('Usage: npx tsx scripts/demo.ts')[1]?.split('*/')[0];
  console.log(`Usage: npx tsx scripts/demo.ts${help ?? ''}`);
  console.log('\nBroadcast commands (create-vault, deposit, deploy-token, spend, replay, recover, drain)');
  console.log('do nothing without --broadcast. --chain 56 additionally requires --allow-mainnet.');
  process.exit(0);
}

function parseArgs(argv: string[]) {
  const flags: Record<string, string | boolean> = {};
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { rest.push(...argv.slice(i + 1)); break; }
    if (a.startsWith('--')) {
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) { flags[a.slice(2)] = next; i++; }
      else flags[a.slice(2)] = true;
    } else rest.push(a);
  }
  return { flags, rest };
}

function fail(message: string): never { throw Object.assign(new Error(message), { safeLocalMessage: true }); }
function ok(message: string): void { console.log(`✓ ${message}`); }
function step(message: string): void { console.log(`\n— ${message}`); }

function chainOf(chainId: number) {
  if (chainId === 97) return bscTestnet;
  if (chainId === 56) return bsc;
  fail('only BSC testnet (97) or mainnet (56) is supported');
}
const explorerOf = (chainId: number) => chainId === 97 ? 'https://testnet.bscscan.com' : 'https://bscscan.com';

function txLink(chainId: number, hash: string) { return `${explorerOf(chainId)}/tx/${hash}`; }

// ------------------------------------------------------------- files & state

interface DemoKeys { deployerPrivateKey: Hex; masterSeed: Hex; createdAt: string }
interface DemoState {
  chainId: number; namespace: string; factory: Address; vault?: Address; token?: Address;
  epochs: Record<string, { root: Hex; recRoot: Hex; seed: Hex }>;
  currentEpoch: number;
  txs: { label: string; hash: Hex }[];
  lastSpend?: { data: Hex; note: string };
  seedEpochs?: number[];
  journalEpochs?: number[];
  pendingDeployment?: Hex;
  pendingRecovery?: RecoveryIntent;
}
interface Journal { nextIndex: number; lastReservation: string | null }

const statePath = (chainId: number) => resolve(ROOT, `demo-state-${chainId}.local`);
const journalPath = (chainId: number, state = existsSync(statePath(chainId)) ? loadState(chainId) : undefined) => {
  const epoch = state?.currentEpoch;
  if (epoch !== undefined && state?.journalEpochs?.includes(epoch)) {
    const root = state.epochs[String(epoch)]?.root;
    if (!root || !/^0x[0-9a-f]{64}$/i.test(root)) fail('Invalid journal root');
    return resolve(ROOT, `demo-journal-${chainId}-${epoch}-${root.slice(2)}.local`);
  }
  return resolve(ROOT, `demo-journal-${chainId}.local`); // existing legacy journals remain readable
};

function atomicWrite(path: string, data: unknown): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`);
  const fd = openSync(tmp, 'r+');
  fsyncSync(fd); closeSync(fd);
  renameSync(tmp, path);
}
function loadKeys(): DemoKeys {
  if (!existsSync(KEYS_PATH)) fail('demo-keys.local not found; run: npx tsx scripts/demo.ts init');
  return JSON.parse(readFileSync(KEYS_PATH, 'utf8')) as DemoKeys;
}
function loadState(chainId: number): DemoState {
  const path = statePath(chainId);
  if (!existsSync(path)) fail(`no demo state for chain ${chainId}; run create-vault first`);
  const state = JSON.parse(readFileSync(path, 'utf8')) as DemoState;
  if (state.chainId !== chainId) fail(`state file is for chain ${state.chainId}, not ${chainId}`);
  return state;
}
function saveState(state: DemoState): void { atomicWrite(statePath(state.chainId), state); }
function recordTx(state: DemoState, label: string, hash: Hex): void {
  state.txs.push({ label, hash }); saveState(state);
  ok(`${label}: ${txLink(state.chainId, hash)}`);
}

function loadJournal(chainId: number): Journal {
  const path = journalPath(chainId);
  if (!existsSync(path)) fail('signing journal missing — refusing to sign (no reconstruction from chain state)');
  const j = JSON.parse(readFileSync(path, 'utf8')) as Journal;
  if (!Number.isSafeInteger(j.nextIndex) || j.nextIndex < 0) fail('signing journal is corrupt — refusing to sign');
  return j;
}
/** Persist the reservation BEFORE the caller signs. Mirrors the real journal's rule. */
function reserveIndex(chainId: number, chainNext: number, selected?: number): number {
  const j = loadJournal(chainId);
  const idx = reserveDemoIndex(j.nextIndex, chainNext, selected);
  const next: Journal = { nextIndex: idx + 1, lastReservation: randomBytes(16).toString('hex') };
  if (existsSync(journalPath(chainId))) writeFileSync(`${journalPath(chainId)}.bak`, `${JSON.stringify(j, null, 2)}\n`);
  atomicWrite(journalPath(chainId), next);
  return idx;
}

// ------------------------------------------------------------------- clients

function makeClients(chainId: number) {
  const chain = chainOf(chainId);
  const url = process.env.RPC_URL || chain.rpcUrls.default.http[0];
  const pub = createPublicClient({ chain, transport: http(url, { timeout: 20_000, retryCount: 2 }) });
  return { chain, pub, url };
}
function makeWallet(chainId: number, keys: DemoKeys) {
  const { chain, pub } = makeClients(chainId);
  const account = privateKeyToAccount(keys.deployerPrivateKey);
  const wallet = createWalletClient({ chain, account, transport: http(process.env.RPC_URL || chain.rpcUrls.default.http[0], { timeout: 20_000, retryCount: 2 }) });
  return { account, wallet, pub, chain };
}

// ------------------------------------------------------------ crypto helpers

async function deriveKey(chainId: number, state: DemoState, epoch: number): Promise<{ key: CchsKey; engine: Awaited<ReturnType<typeof fastCchs>> }> {
  const keys = loadKeys();
  const seed = state.seedEpochs?.includes(epoch)
    ? parseSeedBackup(readFileSync(recoveryBackupPath(chainId, epoch), 'utf8')).seed
    : Uint8Array.from(Buffer.from(keys.masterSeed.slice(2), 'hex'));
  const engine = await fastCchs();
  return { key: deriveAccountKey(seed, scopeFor(chainId as ChainId, state.factory, epoch, NAMESPACE)), engine };
}

const recoveryBackupPath = (chainId: number, epoch: number) => resolve(ROOT, `demo-recovery-backup-${chainId}-${epoch}.local`);

function pubsFor(state: DemoState, epoch: number) {
  const e = state.epochs[String(epoch)];
  if (!e) fail(`no stored public key for epoch ${epoch}`);
  return {
    root: Uint8Array.from(Buffer.from(e.root.slice(2), 'hex')),
    recRoot: Uint8Array.from(Buffer.from(e.recRoot.slice(2), 'hex')),
    seed: Uint8Array.from(Buffer.from(e.seed.slice(2), 'hex')),
  };
}

async function gasPriceOrUndefined(pub: ReturnType<typeof createPublicClient>): Promise<bigint | undefined> {
  const gp = await pub.getGasPrice();
  return gp === 0n ? undefined : gp;
}

// ------------------------------------------------------------------ commands

async function cmdInit(chainId: number): Promise<void> {
  if (existsSync(KEYS_PATH)) fail('demo-keys.local already exists; refusing to overwrite an existing wallet');
  const keys: DemoKeys = {
    deployerPrivateKey: generatePrivateKey(),
    masterSeed: `0x${randomBytes(32).toString('hex')}` as Hex,
    createdAt: new Date().toISOString(),
  };
  atomicWrite(KEYS_PATH, keys);
  const account = privateKeyToAccount(keys.deployerPrivateKey);
  ok('demo wallet + quantum master seed generated');
  console.log(`  Deployer address (fund with ${chainId === 97 ? 'tBNB (BSC testnet)' : 'BNB (BSC mainnet)'}): ${account.address}`);
  console.log(`  Key file: demo-keys.local (gitignored; contents are never printed; keep private)`);
  console.log(`  Next: after funding, run create-vault --chain ${chainId} --broadcast`);
}

async function cmdStatus(chainId: number): Promise<void> {
  const keys = loadKeys();
  const { pub } = makeClients(chainId);
  const account = privateKeyToAccount(keys.deployerPrivateKey);
  console.log(`chain ${chainId} | deployer ${account.address}`);
  console.log(`deployer balance: ${formatEther(await pub.getBalance({ address: account.address }))} ${chainId === 97 ? 'tBNB' : 'BNB'}`);
  if (!existsSync(statePath(chainId))) { console.log('(no vault state yet)'); return; }
  const state = loadState(chainId);
  console.log(`factory: ${state.factory}`);
  if (state.token) console.log(`demo token: ${state.token}`);
  if (!state.vault) return;
  const vault = state.vault;
  const [globals, lane, balance] = await Promise.all([
    readVaultGlobals(pub, vault), readLane(pub, vault, 0), pub.getBalance({ address: vault }),
  ]);
  console.log(`vault: ${vault}`);
  console.log(`vault balance: ${formatEther(balance)} | epoch ${globals.epoch} | recNonce ${globals.recNonce} | lane0 next ${lane.nextIdx} nonce ${lane.nonce}`);
  if (state.token) {
    const tb = await pub.readContract({ address: state.token, abi: DEMO_TOKEN_ABI, functionName: 'balanceOf', args: [vault] }) as bigint;
    console.log(`demo token balance of vault: ${tb}`);
  }
  if (existsSync(journalPath(chainId))) console.log(`journal nextIndex: ${loadJournal(chainId).nextIndex}`);
  for (const t of state.txs) console.log(`  ${t.label}: ${txLink(chainId, t.hash)}`);
}

async function cmdCreateVault(chainId: number, flags: Record<string, string | boolean>): Promise<void> {
  const keys = loadKeys();
  const { pub } = makeClients(chainId);
  if (existsSync(statePath(chainId))) {
    const previous = loadState(chainId);
    if (previous.pendingDeployment) {
      const receipt = await pub.getTransactionReceipt({ hash: previous.pendingDeployment }).catch(() => null);
      if (!receipt) fail('Existing creation is pending; do not submit another transaction.');
      if (receipt.status !== 'success') fail('Existing creation reverted; preserve the state and inspect its transaction.');
      delete previous.pendingDeployment; saveState(previous);
      ok('Previously submitted creation confirmed.'); return;
    }
    if (previous.vault) fail('An existing vault record is present; use status rather than overwrite it.');
  }
  const factory = (flags.factory as Address | undefined) ?? (() => {
    const dir = resolve(ROOT, 'deployments');
    if (!existsSync(dir)) fail(`no factory address: pass --factory or run scripts/deploy.mjs --chain ${chainId} --broadcast first`);
    const files = readdirSync(dir).filter(f => f.startsWith(`${chainId}-`) && f.endsWith('.json'))
      .map(f => ({ f, m: statSync(resolve(dir, f)).mtimeMs })).sort((a, b) => b.m - a.m);
    if (!files.length) fail(`no deployment record for chain ${chainId}; pass --factory`);
    const rec = JSON.parse(readFileSync(resolve(dir, files[0].f), 'utf8'));
    return rec.factory as Address;
  })();

  step(`keygen for epoch 0 (≈1.3M hashes; 1-3 s)`);
  const engine = await fastCchs();
  const seed = Uint8Array.from(Buffer.from(keys.masterSeed.slice(2), 'hex'));
  const key = deriveAccountKey(seed, scopeFor(chainId as ChainId, factory, 0, NAMESPACE));
  const t0 = performance.now();
  const pubs = engine.keygen(key);
  console.log(`  keygen ${((performance.now() - t0) / 1000).toFixed(2)} s`);

  const roots = [toHex(pubs.root), toHex(pubs.recRoot), toHex(pubs.seed)] as const;
  const predictedOffline = predictVaultAddress(factory, roots[0], roots[1], roots[2]);
  const predictedOnchain = await pub.readContract({ address: factory, abi: FABI, functionName: 'predict', args: roots }) as Address;
  if (predictedOffline.toLowerCase() !== predictedOnchain.toLowerCase()) fail('CREATE2 prediction mismatch between local and on-chain');
  console.log(`  vault address (predicted): ${predictedOffline}`);
  const already = await pub.getCode({ address: predictedOffline });
  if (already && already !== '0x') fail('This vault already exists. Inspect it with status; its local signing history must not be overwritten.');

  const value = flags.fund ? parseEther(String(flags.fund)) : 0n;
  const { wallet } = makeWallet(chainId, keys);
  const hash = await wallet.sendTransaction({
    to: factory, data: encodeFactoryDeploy(roots[0], roots[1], roots[2]), value,
    gasPrice: await gasPriceOrUndefined(pub),
  });
  const state: DemoState = {
    chainId, namespace: NAMESPACE, factory, vault: predictedOffline,
    epochs: { '0': { root: roots[0], recRoot: roots[1], seed: roots[2] } },
    currentEpoch: 0, txs: [], pendingDeployment: hash, journalEpochs: [0],
  };
  saveState(state);
  initializeDemoJournal(journalPath(chainId));
  recordTx(state, 'create-vault', hash);
  const receipt = await pub.waitForTransactionReceipt({ hash });
  if (receipt.status !== 'success') fail(`create-vault reverted: ${txLink(chainId, hash)}`);
  const code = await pub.getCode({ address: predictedOffline });
  if (!code || code === '0x') fail('vault code missing after deploy');
  delete state.pendingDeployment; saveState(state);
}

async function cmdDeposit(chainId: number, flags: Record<string, string | boolean>): Promise<void> {
  const state = loadState(chainId);
  if (!state.vault) fail('vault not created yet');
  const amount = flags.amount ? String(flags.amount) : null;
  if (!amount) fail('usage: deposit --amount 0.05 --broadcast');
  const keys = loadKeys();
  const value = parseEther(amount);
  const { pub } = makeClients(chainId);
  const { wallet } = makeWallet(chainId, keys);
  const hash = await wallet.sendTransaction({ to: state.vault, value, gasPrice: await gasPriceOrUndefined(pub) });
  await pub.waitForTransactionReceipt({ hash });
  recordTx(state, `deposit ${amount}`, hash);
}

const DEMO_TOKEN_SOURCE = 'pragma solidity ^0.8.28; contract DemoToken { mapping(address=>uint256) public balanceOf; function mint(address a,uint256 n) external {balanceOf[a]+=n;} function transfer(address a,uint256 n) external returns(bool){require(balanceOf[msg.sender]>=n);balanceOf[msg.sender]-=n;balanceOf[a]+=n;return true;} }';
const DEMO_TOKEN_ABI = [
  { type: 'function', name: 'balanceOf', stateMutability: 'view', inputs: [{ name: 'a', type: 'address' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'mint', stateMutability: 'nonpayable', inputs: [{ name: 'a', type: 'address' }, { name: 'n', type: 'uint256' }], outputs: [] },
  { type: 'function', name: 'transfer', stateMutability: 'nonpayable', inputs: [{ name: 'a', type: 'address' }, { name: 'n', type: 'uint256' }], outputs: [{ type: 'bool' }] },
] as unknown as import('viem').Abi;

async function cmdDeployToken(chainId: number, flags: Record<string, string | boolean>): Promise<void> {
  const state = loadState(chainId);
  if (!state.vault) fail('vault not created yet');
  const mint = flags.mint ? BigInt(String(flags.mint)) : 1_000_000n;
  const keys = loadKeys();
  const { pub } = makeClients(chainId);
  const { wallet } = makeWallet(chainId, keys);
  const output = JSON.parse(solc.compile(JSON.stringify({
    language: 'Solidity',
    sources: { 'DemoToken.sol': { content: DEMO_TOKEN_SOURCE } },
    settings: { evmVersion: 'cancun', outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } },
  })));
  if (output.errors?.some((e: { severity: string }) => e.severity === 'error')) fail('token compile failed');
  const token = output.contracts['DemoToken.sol'].DemoToken as { evm: { bytecode: { object: string } } };
  const gasPrice = await gasPriceOrUndefined(pub);
  const deployHash = await wallet.deployContract({ abi: DEMO_TOKEN_ABI, bytecode: `0x${token.evm.bytecode.object}` as Hex, gasPrice });
  const deployReceipt = await pub.waitForTransactionReceipt({ hash: deployHash });
  if (deployReceipt.status !== 'success' || !deployReceipt.contractAddress) fail('token deploy failed');
  state.token = deployReceipt.contractAddress; saveState(state);
  recordTx(state, 'deploy-token', deployHash);
  const mintHash = await wallet.writeContract({ address: state.token, abi: DEMO_TOKEN_ABI, functionName: 'mint', args: [state.vault, mint], gasPrice: await gasPriceOrUndefined(pub) });
  await pub.waitForTransactionReceipt({ hash: mintHash });
  recordTx(state, `mint ${mint} tokens to vault`, mintHash);
}

async function cmdSpend(chainId: number, flags: Record<string, string | boolean>): Promise<void> {
  const state = loadState(chainId);
  if (!state.vault) fail('vault not created yet');
  const to = flags.to as Address | undefined;
  if (!to) fail('usage: spend --to 0x.. (--value 0.01 | --token --amount 250) [--idx n] --broadcast');
  const keys = loadKeys();
  const { pub } = makeClients(chainId);
  const { wallet } = makeWallet(chainId, keys);

  let target: Address, value: bigint, data: Hex, note: string;
  if (flags.token) {
    if (!state.token) fail('no demo token deployed; run deploy-token first');
    const amount = BigInt(String(flags.amount ?? '250'));
    target = state.token; value = 0n;
    data = encodeTokenTransfer(to, amount);
    note = `token transfer ${amount} -> ${to}`;
  } else {
    const amount = flags.value ? String(flags.value) : '0.01';
    target = to; value = parseEther(amount); data = '0x';
    note = `BNB transfer ${amount} -> ${to}`;
  }

  const lane = await readLane(pub, state.vault, 0);
  const idx = reserveIndex(chainId, Number(lane.nextIdx), flags.idx === undefined ? undefined : Number(flags.idx));
  const needsTop = await readNeedsTopLayer(pub, state.vault, idx);

  const { key, engine } = await deriveKey(chainId, state, state.currentEpoch);
  const digest = executeDigestFor(engine, {
    chainId: chainId as ChainId, vault: state.vault, laneNonce: lane.nonce, idx, target, value, data,
  });
  const onchainDigest = await readDigestAt(pub, state.vault, idx, target, value, data);
  if (toHex(digest) !== onchainDigest.toLowerCase()) fail(`digest mismatch with chain (${toHex(digest)} vs ${onchainDigest}) — refusing to sign`);

  const trees = new Map<string, Tree>();
  const sig = engine.sign(key, idx, digest, !needsTop, trees);
  const bottom = trees.get(`0/${idx >> 10}`)!.root;
  engine.verify(pubsFor(state, state.currentEpoch), idx, digest, sig, sig.l1 ? undefined : bottom); // local sanity before sending

  const method = sig.l1 ? 'executeFirst' : 'execute';
  const txData = encodeExecuteCall(idx, target, value, data, sig);
  state.lastSpend = { data: txData, note };
  saveState(state);

  console.log(`  leaf idx ${idx} | ${method} | ${note} | signature ${signatureBytes(sig)} B | calldata ${(txData.length - 2) / 2} B`);
  const gasEstimate = await pub.estimateGas({ account: wallet.account, to: state.vault, data: txData, value: 0n });
  const gas = (gasEstimate * 130n) / 100n;
  const hash = await wallet.sendTransaction({ to: state.vault, data: txData, gas, gasPrice: await gasPriceOrUndefined(pub) });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  if (receipt.status !== 'success') fail(`spend reverted: ${txLink(chainId, hash)}`);
  recordTx(state, `spend #${idx} (${method})`, hash);
  console.log(`  gasUsed ${receipt.gasUsed}`);
}

async function cmdReplay(chainId: number, flags: Record<string, string | boolean>): Promise<void> {
  const state = loadState(chainId);
  if (!state.vault || !state.lastSpend) fail('nothing to replay yet');
  const { pub } = makeClients(chainId);
  step('Simulate with eth_call (no gas spent) and check whether the contract rejects the replay');
  const error = await requireRejectedReplay(() => pub.call({ to: state.vault!, data: state.lastSpend!.data }));
  const name = vaultErrorName(error);
  if (!name) fail('Cannot distinguish a contract replay rejection from a node error; nothing was broadcast');
  ok(`Replay rejected: ${name} (${state.lastSpend.note})`);
  const keys = loadKeys();
  const { wallet } = makeWallet(chainId, keys);
  const hash = await wallet.sendTransaction({ to: state.vault, data: state.lastSpend.data, gas: 3_000_000n, gasPrice: await gasPriceOrUndefined(pub) });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  if (receipt.status === 'success') fail('replayed tx landed — reproduction case captured, stop the demo');
  recordTx(state, 'replay rejected (expected revert)', hash);
}

async function cmdRecover(chainId: number, flags: Record<string, string | boolean>): Promise<void> {
  const state = loadState(chainId);
  if (!state.vault) fail('vault not created yet');
  const { pub } = makeClients(chainId);
  const current = await readVaultKey(pub, state.vault);
  const asRecord = (): VaultRecord => ({ chainId: chainId as ChainId, factory: state.factory, vault: state.vault!, namespace: NAMESPACE,
    accountIndex: '0', createdAt: '', currentEpoch: String(state.currentEpoch), txs: state.txs,
    epochs: Object.fromEntries(Object.entries(state.epochs).map(([e, p]) => [e, { root: p.root, recRoot: p.recRoot, pkSeed: p.seed }])),
    pendingRecovery: state.pendingRecovery });
  if (!state.pendingRecovery) {
    if (Number(current.epoch) !== state.currentEpoch || current.root.toLowerCase() !== state.epochs[String(state.currentEpoch)]?.root.toLowerCase()) fail('chain key differs from local state');
    if (current.recNonce >= 256n) fail('recovery capacity exhausted');
    const nextEpoch = state.currentEpoch + 1;
    const path = recoveryBackupPath(chainId, nextEpoch);
    if (existsSync(path)) fail('A recovery backup already exists: preserve it and restore the matching pending intent.');
    const seed = new Uint8Array(randomBytes(32));
    const engine = await fastCchs();
    const newKey = deriveAccountKey(seed, scopeFor(chainId as ChainId, state.factory, nextEpoch, NAMESPACE));
    const pk = engine.keygen(newKey);
    const newPublicKey = { root: toHex(pk.root), recRoot: toHex(pk.recRoot), pkSeed: toHex(pk.seed) };
    const digest = toHex(recoveryDigestFor(engine, { chainId: chainId as ChainId, vault: state.vault, recNonce: current.recNonce,
      newRoot: newPublicKey.root, newRecRoot: newPublicKey.recRoot, newPkSeed: newPublicKey.pkSeed }));
    atomicWrite(path, seedBackupFile(seed, { chainId: chainId as ChainId, factory: state.factory, vault: state.vault,
      namespace: NAMESPACE, accountIndex: '0', epoch: String(nextEpoch), ...newPublicKey }));
    seed.fill(0);
    state.pendingRecovery = { oldEpoch: String(state.currentEpoch), oldRoot: current.root, recNonce: String(current.recNonce),
      newEpoch: String(nextEpoch), newPublicKey, digest, replacesSeed: true };
    saveState(state); // fixed public intent before any recovery signature
    console.log(`New backup saved locally: ${path}. Keep it private and offline.`);
  }
  const intent = state.pendingRecovery;
  const backupPath = recoveryBackupPath(chainId, Number(intent.newEpoch));
  if (!existsSync(backupPath)) fail('New recovery backup is missing; refusing to submit.');
  verifyRecoveryBackup(readFileSync(backupPath, 'utf8'), asRecord(), intent, await fastCchs());
  const finish = () => {
    state.epochs[intent.newEpoch] = { root: intent.newPublicKey.root, recRoot: intent.newPublicKey.recRoot, seed: intent.newPublicKey.pkSeed };
    state.currentEpoch = Number(intent.newEpoch);
    state.seedEpochs = [...new Set([...(state.seedEpochs ?? []), state.currentEpoch])];
    state.journalEpochs = [...new Set([...(state.journalEpochs ?? []), state.currentEpoch])];
    const newJournal = journalPath(chainId, state);
    initializeDemoJournal(newJournal);
    delete state.pendingRecovery;
    saveState(state);
    if (intent.hash) recordTx(state, `recover -> epoch ${intent.newEpoch}`, intent.hash);
  };
  if (recoveryState(asRecord(), current) === 'confirmed') { finish(); return; }
  if (intent.hash) {
    const receipt = await pub.getTransactionReceipt({ hash: intent.hash }).catch(() => null);
    if (!receipt || receipt.status === 'success') fail('Recovery is pending: keep the same intent and retry checking later.');
    delete intent.hash; intent.submissionUncertain = false; saveState(state);
  }
  if (intent.submissionUncertain) fail('Previous wallet submission is uncertain. Check the sender history before resubmitting.');
  if (!intent.calldata) {
    const { key, engine } = await deriveKey(chainId, state, state.currentEpoch);
    const msg = Uint8Array.from(Buffer.from(intent.digest.slice(2), 'hex'));
    const rec = engine.signRecovery(key, Number(intent.recNonce), msg);
    if (!engine.verifyRecovery(pubsFor(state, state.currentEpoch), Number(intent.recNonce), msg, rec)) fail('local recovery signature failed');
    intent.calldata = encodeRecoverCall(intent.newPublicKey.root, intent.newPublicKey.recRoot, intent.newPublicKey.pkSeed, rec);
    saveState(state);
  }
  const { wallet } = makeWallet(chainId, loadKeys());
  await pub.estimateGas({ account: wallet.account, to: state.vault, data: intent.calldata });
  intent.submissionUncertain = true; saveState(state);
  intent.hash = await wallet.sendTransaction({ to: state.vault, data: intent.calldata, gasPrice: await gasPriceOrUndefined(pub) });
  intent.submissionUncertain = false; saveState(state);
  const receipt = await pub.waitForTransactionReceipt({ hash: intent.hash });
  if (receipt.status !== 'success') fail('Recovery reverted. Retry the same saved intent only.');
  if (recoveryState(asRecord(), await readVaultKey(pub, state.vault)) !== 'confirmed') fail('Recovery confirmation mismatch');
  finish();
}

async function cmdDrain(chainId: number, flags: Record<string, string | boolean>): Promise<void> {
  const state = loadState(chainId);
  const to = flags.to as Address | undefined;
  if (!to) fail('usage: drain --to 0x.. --broadcast');
  const keys = loadKeys();
  const { pub } = makeClients(chainId);
  const balance = await pub.getBalance({ address: state.vault! });
  console.log(`  vault BNB: ${formatEther(balance)}`);
  if (balance > 0n) {
    await spendRaw(chainId, state, to, balance, '0x', `drain ${formatEther(balance)} BNB -> ${to}`, flags);
  }
  if (state.token) {
    const tb = await pub.readContract({ address: state.token, abi: DEMO_TOKEN_ABI, functionName: 'balanceOf', args: [state.vault!] }) as bigint;
    if (tb > 0n) {
      const data = encodeTokenTransfer(to, tb);
      await spendRaw(chainId, state, state.token, 0n, data, `drain ${tb} demo tokens -> ${to}`, flags);
    }
  }
  const account = privateKeyToAccount(keys.deployerPrivateKey);
  const leftover = await pub.getBalance({ address: account.address });
  const gasPrice = (await pub.getGasPrice()) || 1n;
  const reserve = 21_000n * gasPrice * 3n;
  if (to.toLowerCase() !== account.address.toLowerCase() && leftover > reserve) {
    const send = leftover - reserve;
    step(`Sweep remaining deployer balance: ${formatEther(send)}`);
    const { wallet } = makeWallet(chainId, keys);
    const hash = await wallet.sendTransaction({ to, value: send, gasPrice: await gasPriceOrUndefined(pub) });
    await pub.waitForTransactionReceipt({ hash });
    recordTx(state, `sweep deployer ${formatEther(send)}`, hash);
  }
  ok('Drain complete');
}

/** Shared spend path for drain (same journal discipline as cmdSpend). */
async function spendRaw(chainId: number, state: DemoState, target: Address, value: bigint, data: Hex, note: string, flags: Record<string, string | boolean>): Promise<void> {
  const keys = loadKeys();
  const { pub } = makeClients(chainId);
  const { wallet } = makeWallet(chainId, keys);
  const lane = await readLane(pub, state.vault!, 0);
  const idx = reserveIndex(chainId, Number(lane.nextIdx));
  const needsTop = await readNeedsTopLayer(pub, state.vault!, idx);
  const { key, engine } = await deriveKey(chainId, state, state.currentEpoch);
  const digest = executeDigestFor(engine, {
    chainId: chainId as ChainId, vault: state.vault!, laneNonce: lane.nonce, idx, target, value, data,
  });
  const onchainDigest = await readDigestAt(pub, state.vault!, idx, target, value, data);
  if (toHex(digest) !== onchainDigest.toLowerCase()) fail('digest mismatch with chain — refusing to sign');
  const trees = new Map<string, Tree>();
  const sig = engine.sign(key, idx, digest, !needsTop, trees);
  const bottom = trees.get(`0/${idx >> 10}`)!.root;
  engine.verify(pubsFor(state, state.currentEpoch), idx, digest, sig, sig.l1 ? undefined : bottom);
  const method = sig.l1 ? 'executeFirst' : 'execute';
  const txData = encodeExecuteCall(idx, target, value, data, sig);
  console.log(`  leaf ${idx} | ${method} | ${note} | ${signatureBytes(sig)} B`);
  const gasEstimate = await pub.estimateGas({ account: wallet.account, to: state.vault!, data: txData });
  const hash = await wallet.sendTransaction({ to: state.vault!, data: txData, gas: (gasEstimate * 130n) / 100n, gasPrice: await gasPriceOrUndefined(pub) });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  if (receipt.status !== 'success') fail(`drain spend reverted: ${txLink(chainId, hash)}`);
  recordTx(state, note, hash);
}

function encodeTokenTransfer(to: Address, amount: bigint): Hex {
  return encodeFunctionData({ abi: DEMO_TOKEN_ABI, functionName: 'transfer', args: [to, amount] } as never);
}

// --------------------------------------------------------------------- main

async function main(): Promise<void> {
  const { flags, rest } = parseArgs(process.argv.slice(2));
  if (flags.help || rest.length === 0) usage();
  const chainId = flags.chain ? Number(flags.chain) : 97;
  chainOf(chainId);
  const command = rest[0];
  if (!broadcastAllowed(command, chainId, flags)) {
    console.log(`Dry run: ${command} on chain ${chainId}. No keys read, signatures, state writes or transactions. Writes require --broadcast and mainnet also --allow-mainnet.`);
    return;
  }
  await withDemoLock(ROOT, async () => {
  switch (command) {
    case 'init': return cmdInit(chainId);
    case 'status': return cmdStatus(chainId);
    case 'create-vault': return cmdCreateVault(chainId, flags);
    case 'deposit': return cmdDeposit(chainId, flags);
    case 'deploy-token': return cmdDeployToken(chainId, flags);
    case 'spend': return cmdSpend(chainId, flags);
    case 'replay': return cmdReplay(chainId, flags);
    case 'recover': return cmdRecover(chainId, flags);
    case 'drain': return cmdDrain(chainId, flags);
    default: fail(`unknown command: ${command} (see --help)`);
  }
  });
}

main().catch((error: unknown) => {
  // RPC/library errors may embed credentials or signed payloads. Do not echo them.
  console.error((error as { safeLocalMessage?: boolean }).safeLocalMessage ? (error as Error).message : 'Demo command failed. Check inputs, the local state and the RPC; error payload withheld.');
  process.exitCode = 1;
});
