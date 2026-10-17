import { useEffect, useRef, useState } from 'react';
import { bytesToHex, formatEther, hexToBytes, parseEther, type Address, type Hex } from 'viem';
import { connectWallet, NETWORKS } from './services';
import * as vault from './vault/client';
import * as ops from './vault/ops';
import type { RecoveryIntent, VaultPublicKey, VaultRecord } from './vault/types';
import { readVaultKey } from './vault/chain';
import { getPublicClient } from './services';
import { samePublicKey } from './vault/recovery';

type ChainId = 56 | 97;
type Wallet = { address: string; balance: string };
const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;
const msg = (e: unknown) => (e instanceof Error ? e.message : 'The operation did not complete. Please try again.');

export default function VaultPage({ chainId, onHelp }: { chainId: ChainId; onHelp?: () => void }) {
  const [wallet, setWallet] = useState<Wallet | null>(null);
  const [walletBusy, setWalletBusy] = useState(false);
  const [record, setRecord] = useState<VaultRecord | null>(() => vault.recordForChain(chainId));
  const [dashboard, setDashboard] = useState<vault.VaultDashboard | null>(null);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [keyLoaded, setKeyLoaded] = useState(false);
  const busyRef = useRef(false);

  const [createOpen, setCreateOpen] = useState(false);
  const [seedDisplay, setSeedDisplay] = useState('');
  const [seedRawHex, setSeedRawHex] = useState('');
  const [seedRevealed, setSeedRevealed] = useState(false);
  const [seedConfirm, setSeedConfirm] = useState('');
  const [publicKey, setPublicKey] = useState<VaultPublicKey | null>(null);
  const [predicted, setPredicted] = useState('');
  const [fundValue, setFundValue] = useState('0.002');
  const [deployHash, setDeployHash] = useState('');
  const [backupAcknowledged, setBackupAcknowledged] = useState(false);

  const [importText, setImportText] = useState('');
  const [importOpen, setImportOpen] = useState(false);

  const [depositValue, setDepositValue] = useState('0.002');
  const [execTo, setExecTo] = useState('');
  const [execValue, setExecValue] = useState('0.001');
  const [execData, setExecData] = useState('');
  const [execAdvanced, setExecAdvanced] = useState(false);
  const [preview, setPreview] = useState<vault.ExecutePreview | null>(null);
  const [recoverConfirm, setRecoverConfirm] = useState(false);
  const [recoverySeed, setRecoverySeed] = useState('');
  const [recoveryCheck, setRecoveryCheck] = useState('');
  const [recoveryDraft, setRecoveryDraft] = useState<RecoveryIntent | null>(null);
  const [recoveryTxHash, setRecoveryTxHash] = useState('');

  function clearSecretFields() {
    setSeedRawHex(''); setSeedDisplay(''); setSeedConfirm(''); setSeedRevealed(false);
    setImportText(''); setRecoverySeed(''); setRecoveryCheck(''); setRecoveryDraft(null);
    setPublicKey(null); setKeyLoaded(false); setBackupAcknowledged(false); setRecoverConfirm(false);
  }

  const factory = ops.FACTORY[chainId];
  const net = NETWORKS[chainId];

  useEffect(() => {
    void vault.lockKeyMaterial(); clearSecretFields(); setCreateOpen(false); setImportOpen(false);
    setRecord(vault.recordForChain(chainId));
    setDashboard(null); setPreview(null); setWallet(null); setError(''); setNotice('');
  }, [chainId]);

  useEffect(() => () => { void vault.lockKeyMaterial(); }, []);

  useEffect(() => { void refreshDashboard(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [record?.vault, chainId]);

  async function refreshDashboard() {
    const current = vault.recordForChain(chainId);
    if (!current) return;
    try {
      await vault.reconcileTransactions(current);
      if (await vault.reconcileRecovery(current)) {
        clearSecretFields(); setNotice('Key rotation is confirmed on-chain. Import the new backup you saved.');
      }
      if (current.pendingDeployment) {
        const receipt = await vault.receiptNow(chainId, current.pendingDeployment);
        if (!receipt) { setNotice('Vault deployment is still pending. Refresh again later.'); return; }
        if (receipt.status !== 'success') throw new Error('Vault deployment reverted. Keep your backup and inspect the transaction.');
        delete current.pendingDeployment; vault.saveRecord(current);
      }
      setRecord({ ...current });
      setDashboard(await vault.readDashboard(chainId, current));
    } catch (e) { setDashboard(null); setError(msg(e)); }
  }

  async function run(label: string, fn: () => Promise<void>): Promise<void> {
    if (busyRef.current) return;
    busyRef.current = true; setBusy(label); setError('');
    try { await fn(); } catch (e) { setError(msg(e)); }
    finally { busyRef.current = false; setBusy(''); }
  }

  async function handleConnect() {
    setWalletBusy(true); setError('');
    try { setWallet(await connectWallet(chainId)); }
    catch (e) { setError(msg(e)); }
    finally { setWalletBusy(false); }
  }

  // ------------------------------------------------------------- create flow
  async function generateSeed() {
    await run('Generating backup code…', async () => {
      const raw = await vault.generateSeedInWorker();
      setSeedRawHex(raw);
      setSeedDisplay(ops.encodeSeedWithChecksum(hexToBytes(raw as `0x${string}`)));
      setSeedRevealed(false); setSeedConfirm(''); setPublicKey(null); setPredicted(''); setDeployHash('');
      setBackupAcknowledged(false);
      setKeyLoaded(false);
    });
  }

  function downloadBackup() {
    if (!seedRawHex) return;
    const seedBytes = hexToBytes(seedRawHex as `0x${string}`);
    const publicFields = publicKey && factory
      ? {
        chainId, namespace: ops.WEB_NAMESPACE, accountIndex: '0', epoch: '0',
        root: publicKey.root, recRoot: publicKey.recRoot, pkSeed: publicKey.pkSeed,
        factory, vault: ops.predictVaultAddress(factory, publicKey.root, publicKey.recRoot, publicKey.pkSeed),
      }
      : undefined;
    const blob = new Blob([`${JSON.stringify(ops.seedBackupFile(seedBytes, publicFields), null, 2)}\n`], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url; link.download = 'EVM-Quantum-Vault-backup.json'; link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 5_000);
  }

  async function confirmSeedAndKeygen() {
    await run('Generating vault keys…', async () => {
      if (!seedRawHex) throw new Error('Generate a backup code first.');
      const entered = ops.decodeSeedWithChecksum(seedConfirm);
      if (bytesToHex(entered).toLowerCase() !== seedRawHex.toLowerCase()) throw new Error('The entered code does not match the backup. Please check it again.');
      if (!factory) throw new Error('No vault factory is configured for this network. Configure a deployment before creating a vault.');
      const pk = await vault.keygenFor(chainId, factory, ops.WEB_NAMESPACE, '0', '0', undefined, (label) => setBusy(label));
      setPublicKey(pk);
      setPredicted(await vault.previewVaultAddress(chainId, factory, pk));
      setKeyLoaded(true);
    });
  }

  async function deployWithFunding() {
    await run('Confirm the deployment transaction in your wallet…', async () => {
      if (!wallet) throw new Error('Connect a wallet to pay deployment gas.');
      if (!publicKey || !factory) throw new Error('Verify your backup and generate the vault keys first.');
      const value = fundValue.trim() ? parseEther(fundValue.trim()) : 0n;
      const { vault: vaultAddress, hash, pending } = await vault.deployVault({ chainId, factory, publicKey, fundValueWei: value, from: wallet.address as Address,
        onSubmitted: async ({ vault: address, hash: txHash }) => {
          const submitted: VaultRecord = { chainId, factory, vault: address, namespace: ops.WEB_NAMESPACE, accountIndex: '0',
            createdAt: new Date().toISOString(), epochs: { '0': publicKey }, currentEpoch: '0',
            txs: [{ label: 'Create vault', hash: txHash, status: 'pending' }], pendingDeployment: txHash };
          vault.saveRecord(submitted); setRecord(submitted);
          await vault.initializeJournal(submitted, 0);
        } });
      setDeployHash(hash);
      const created: VaultRecord = {
        chainId, factory, vault: vaultAddress, namespace: ops.WEB_NAMESPACE, accountIndex: '0',
        createdAt: new Date().toISOString(), epochs: { '0': publicKey }, currentEpoch: '0',
        txs: [{ label: 'Create vault', hash, status: pending ? 'pending' : 'success' }],
        ...(pending ? { pendingDeployment: hash } : {}),
      };
      vault.saveRecord(created);
      setRecord(created);
      setCreateOpen(false);
      setSeedRevealed(false); // keep seedRawHex/publicKey so the backup file stays downloadable until acknowledged
      setNotice(pending ? `Deployment submitted and awaiting confirmation: ${vault.explorerTx(chainId, hash)}` : `Vault deployed: ${vaultAddress}.`);
      await refreshDashboard();
    });
  }

  // ------------------------------------------------------------- import flow
  async function importExisting() {
    await run('Verifying and loading backup…', async () => {
      const parsed = ops.parseSeedBackup(importText);
      setKeyLoaded(false);
      await vault.importSeedToWorker(bytesToHex(parsed.seed));
      const existing = vault.recordForChain(chainId);
      const hints = parsed.publicFields;
      if (hints?.chainId !== undefined && hints.chainId !== chainId) throw new Error('The backup belongs to a different network.');
      const useExisting = existing && (!hints?.vault || hints.vault.toLowerCase() === existing.vault.toLowerCase()) ? existing : null;
      const factoryAddress = (hints?.factory ?? useExisting?.factory ?? ops.FACTORY[chainId]) as Address | undefined;
      if (!factoryAddress) throw new Error('No factory address was found. Configure a factory or import a complete backup containing the vault details.');
      let address = hints?.vault ?? useExisting?.vault;
      if (!address) {
        const initial = await vault.keygenFor(chainId, factoryAddress, hints?.namespace ?? ops.WEB_NAMESPACE, hints?.accountIndex ?? '0', '0');
        address = ops.predictVaultAddress(factoryAddress, initial.root, initial.recRoot, initial.pkSeed);
        await vault.importSeedToWorker(bytesToHex(parsed.seed));
      }
      const chainKey = await readVaultKey(getPublicClient(chainId), address as Address);
      const epochToLoad = chainKey ? String(chainKey.epoch) : (hints?.epoch ?? '0');
      const pk = await vault.keygenFor(chainId, factoryAddress, hints?.namespace ?? useExisting?.namespace ?? ops.WEB_NAMESPACE, hints?.accountIndex ?? useExisting?.accountIndex ?? '0', epochToLoad, undefined, (label) => setBusy(label));
      if (chainKey && !samePublicKey(pk, chainKey)) throw new Error('This backup does not match the active on-chain key. Import the new backup created during key rotation.');
      if (useExisting) {
        useExisting.epochs[epochToLoad] = pk; useExisting.currentEpoch = epochToLoad;
        vault.saveRecord(useExisting); setRecord(useExisting);
      } else {
        setRecord(await vault.adoptFromBackup(chainId, { ...(hints ?? { namespace: ops.WEB_NAMESPACE, accountIndex: '0' }),
          chainId, factory: factoryAddress, vault: address, epoch: epochToLoad, ...pk }, pk));
        setNotice('Public vault details were restored from the backup. Missing signing history was not restored; preserve the original browser and recovery records.');
      }
      setKeyLoaded(true); setImportOpen(false); setImportText('');
      await refreshDashboard();
    });
  }

  async function runDeposit() {
    await run('Confirm the deposit in your wallet…', async () => {
      if (!record) throw new Error('No vault is open.');
      if (!wallet) throw new Error('Connect your wallet first.');
      const amount = depositValue.trim();
      if (!amount) throw new Error('Enter the amount to deposit.');
      const value = parseEther(amount);
      if (value <= 0n) throw new Error('The deposit amount must be greater than zero.');
      const outcome = await vault.depositToVault({ chainId, record, from: wallet.address as Address, valueWei: value });
      setNotice(outcome.pending
        ? `Deposit of ${amount} BNB submitted: ${vault.explorerTx(chainId, outcome.hash)}. Refresh on-chain state later to update the balance.`
        : `Deposited ${amount} BNB: ${vault.explorerTx(chainId, outcome.hash)}`);
      await refreshDashboard();
    });
  }

  function exitVault() {
    if (!record) return;
    if (!window.confirm('Close this vault?\n\nThis removes its local display record. On-chain assets are unaffected. You can import the vault again using its backup.')) return;
    vault.removeRecord(record.chainId, record.vault);
    void vault.lockKeyMaterial(); clearSecretFields();
    setRecord(null); setDashboard(null); setPreview(null);
    setNotice('Vault closed. Create a new vault or import an existing backup.');
  }

  async function doLock() {
    await run('Clearing key material…', async () => {
      await vault.lockKeyMaterial();
      clearSecretFields();
      setNotice('The signing worker has stopped and the page has cleared its backup data. Import your backup to continue.');
    });
  }

  // ------------------------------------------------------------ execute flow
  function buildExecRequest(): vault.ExecuteRequest {
    const target = execTo.trim() as Address;
    if (!/^0x[0-9a-fA-F]{40}$/.test(target)) throw new Error('Invalid recipient address. Enter a 42-character address beginning with 0x.');
    const data = (execAdvanced && execData.trim() ? execData.trim() : '0x') as Hex;
    const value = execValue.trim() ? parseEther(execValue.trim()) : 0n;
    return { target, value, data };
  }

  function runPreview() {
    void run('Reading and checking on-chain state…', async () => {
      if (!record) throw new Error('No vault is open.');
      setPreview(await vault.previewExecute(chainId, record, buildExecRequest()));
    });
  }

  async function runExecute() {
    await run('Executing…', async () => {
      if (!record) throw new Error('No vault is open.');
      if (!wallet) throw new Error('Connect a wallet to pay gas. The vault transfer is authorized by a one-time signature.');
      const outcome = await vault.executeVault({
        chainId, record, request: buildExecRequest(), from: wallet.address as Address,
        onProgress: (label) => setBusy(label),
      });
      setPreview(null);
      setNotice(outcome.pending
        ? `Transaction submitted; receipt not yet available. Do not resend. Check the result later: ${outcome.explorer}`
        : `Execution confirmed using signature index ${outcome.idx}: ${outcome.explorer}`);
      await refreshDashboard();
    });
  }

  async function doRecover() {
    await run('Preparing key rotation…', async () => {
      if (!record) throw new Error('No vault is open.');
      if (!wallet) throw new Error('Connect your wallet first.');
      if (!record.pendingRecovery) {
        if (!recoveryDraft || !recoverySeed) throw new Error('Generate and save the new backup first.');
        if (bytesToHex(ops.decodeSeedWithChecksum(recoveryCheck)).toLowerCase() !== recoverySeed.toLowerCase()) throw new Error('The new backup code does not match.');
        await vault.saveRecovery(record, recoveryDraft);
      }
      const outcome = await vault.recoverVault({ chainId, record, from: wallet.address as Address, onProgress: (label) => setBusy(label) });
      setRecoverConfirm(false);
      setRecord({ ...record });
      setNotice(outcome.pending
        ? `Key rotation is pending: ${outcome.explorer}. Refresh to check it; do not create another recovery plan.`
        : `Key rotation confirmed at epoch ${outcome.newEpoch}. Import your new backup. ${outcome.explorer}`);
      if (!outcome.pending) clearSecretFields();
      await refreshDashboard();
    });
  }

  async function startRecovery() {
    await run('Generating independent replacement keys…', async () => {
      if (!record || !keyLoaded) throw new Error('Import the current backup first.');
      const raw = await vault.generateRecoverySeed();
      const draft = await vault.prepareRecovery(record, raw as Hex, setBusy);
      setRecoverySeed(raw); setRecoveryDraft(draft); setRecoveryCheck(''); setRecoverConfirm(false);
    });
  }

  function downloadRecoveryBackup() {
    if (!record || !recoveryDraft || !recoverySeed) return;
    const p = recoveryDraft.newPublicKey;
    const file = ops.seedBackupFile(hexToBytes(recoverySeed as Hex), { chainId, factory: record.factory, vault: record.vault,
      namespace: record.namespace, accountIndex: record.accountIndex, epoch: recoveryDraft.newEpoch, ...p });
    const url = URL.createObjectURL(new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a'); a.href = url; a.download = `EVM-Quantum-Vault-backup-epoch-${recoveryDraft.newEpoch}.json`; a.click();
    URL.revokeObjectURL(url);
  }

  // ------------------------------------------------------------------ render
  return (
    <div className="vault-page">
      <div className="vault-intro panel">
        <strong>What is a vault?</strong>
        <p>A vault holds your on-chain assets. Your connected wallet pays gas; the vault backup authorizes transfers. Save your backup before depositing assets.</p>
        {onHelp && <button className="text-button" onClick={onHelp}>Read the guide</button>}
      </div>

      <div className="vault-status-bar panel">
        <div className="vault-status-item"><span className="status-dot" />{net.name}</div>
        <div className="vault-status-item">{keyLoaded ? 'Key loaded locally' : 'Key not loaded'}</div>
        <div className="vault-status-actions">
          {keyLoaded && <button className="text-button" onClick={() => void doLock()} disabled={!!busy}>Lock key</button>}
          <button className="button button-wallet" onClick={() => void handleConnect()} disabled={walletBusy}>
            {walletBusy ? 'Connecting…' : wallet ? short(wallet.address) : 'Connect wallet for gas'}
          </button>
        </div>
      </div>

      {error && <div className="notice error" role="alert">{error}</div>}
      {notice && <div className="notice vault-notice" role="status">{notice}
        <button onClick={() => setNotice('')} aria-label="Dismiss notice">×</button></div>}
      {busy && <div className="vault-live" role="status">{busy}</div>}

      {!record && !createOpen && (
        <div className="vault-empty panel">
          <h2>No vault is open</h2>
          <p>Create a vault by generating a backup locally, saving it offline, and confirming deployment in your wallet. Signatures derived from the backup authorize transfers. Manage deposits, transfers, and key rotation here.</p>
          <div className="vault-empty-actions">
            <button className="button button-primary" onClick={() => setCreateOpen(true)} disabled={!factory}>Create vault</button>
            <button className="text-button" onClick={() => setImportOpen((v) => !v)}>Import an existing backup</button>
          </div>
          {!factory && <p className="subtle-copy">Vault creation is not configured for {net.name}. You can still import a complete backup for an existing vault.</p>}
        </div>
      )}

      {record && seedRawHex && !backupAcknowledged && !createOpen && (
        <div className="notice vault-backup-warn" role="alert">
          <span>You have not confirmed saving this vault backup. Losing all copies of your key material can make assets <b>permanently inaccessible</b>. Download and store the complete backup now.</span>
          <button className="button" onClick={downloadBackup}>Download backup</button>
          <button className="button button-primary" onClick={() => setBackupAcknowledged(true)}>I saved my backup</button>
        </div>
      )}

      {createOpen && (
        <div className="panel vault-wizard">
          <div className="section-title"><h2>Create vault</h2><span className="soft-badge">Step {seedDisplay ? (publicKey ? '3' : '2') : '1'} of 3</span></div>
          {!seedDisplay && <>
            <p className="panel-description">Step 1: generate a <strong>backup code</strong> locally. It contains the key material controlling this vault. <strong>Losing it can make assets unrecoverable; sharing it gives others control.</strong> Download and record it immediately.</p>
            <button className="button button-primary" onClick={() => void generateSeed()} disabled={!!busy}>Generate backup code</button>
          </>}
          {seedDisplay && !publicKey && <>
            <p className="panel-description">Step 2: <strong>save your backup offline before continuing.</strong> Download the file, store it somewhere you control, and keep a written copy. Do not upload it to chat or cloud storage. Enter the code below to verify your copy.</p>
            <div className="vault-seed">
              <code>{seedRevealed ? seedDisplay : `${seedDisplay.slice(0, 10)}${'•'.repeat(48)}`}</code>
              <div className="vault-seed-actions">
                <button className="text-button" onClick={() => setSeedRevealed((v) => !v)}>{seedRevealed ? 'Hide' : 'Reveal'}</button>
                <button className="text-button" onClick={downloadBackup}>Download backup</button>
              </div>
            </div>
            <label className="field-label" htmlFor="seed-confirm">Enter your saved backup code<span className="mono">Checks for transcription errors</span></label>
            <textarea id="seed-confirm" value={seedConfirm} onChange={(e) => setSeedConfirm(e.target.value)} rows={3} placeholder="Paste the complete vault backup code" spellCheck={false} />
            <button className="button button-primary vault-next" onClick={() => void confirmSeedAndKeygen()} disabled={!!busy || !seedConfirm.trim()}>Verify and generate keys</button>
          </>}
          {publicKey && <>
            <p className="panel-description">Step 3: your keys are ready locally. Deploy the vault to {net.name} below and confirm the gas fee in your wallet. You may include an initial BNB deposit.</p>
            <dl className="vault-dl">
              <div><dt>Predicted vault address</dt><dd className="mono">{predicted}</dd></div>
              <div><dt>Public key root</dt><dd className="mono">{publicKey.root}</dd></div>
            </dl>
            <label className="field-label" htmlFor="fund">Initial BNB deposit (optional)</label>
            <input id="fund" className="vault-input" value={fundValue} onChange={(e) => setFundValue(e.target.value)} inputMode="decimal" />
            <button className="button button-primary vault-next" onClick={() => void (wallet ? deployWithFunding() : handleConnect())} disabled={!!busy}>{wallet ? 'Deploy vault' : 'Connect wallet first'}</button>
            {deployHash && <p className="subtle-copy mono">{deployHash}</p>}
          </>}
            <div className="vault-reset"><button className="text-button" onClick={() => { setCreateOpen(false); void doLock(); }} disabled={!!busy}>Cancel</button></div>
        </div>
      )}

      {importOpen && (
        <div className="panel vault-import">
          <div className="section-title"><h2>Import backup</h2></div>
          <p className="panel-description">Choose your saved backup file or paste its contents below. The backup code is held in local memory and is not saved to browser storage. Treat any backup shared in a chat as compromised.</p>
          <label className="button vault-file-pick">
            Choose backup file…
            <input
              type="file" accept=".json,.txt,application/json,text/plain" style={{ display: 'none' }}
              onChange={(e) => {
                const file = e.target.files?.[0];
                e.target.value = '';
                if (!file) return;
                file.text().then((text) => setImportText(text)).catch(() => setError('Unable to read the file. Paste its contents instead.'));
              }}
            />
          </label>
          <textarea value={importText} onChange={(e) => setImportText(e.target.value)} rows={4} placeholder='{"format":"bqv-seed-backup-v1",...} or 0x…' spellCheck={false} />
          <button className="button button-primary vault-next" onClick={() => void importExisting()} disabled={!!busy || !importText.trim()}>Verify and load</button>
        </div>
      )}

      {record && !createOpen && (
        <div className="vault-grid">
          <section className="panel vault-dashboard">
            <div className="section-title"><h2>My vault</h2><span className="soft-badge">{net.name}</span></div>
            <div className="vault-balance">{dashboard ? formatEther(dashboard.balance) : '—'}<span>BNB</span></div>
            <a className="address-link mono" href={`${net.explorer}/address/${record.vault}`} target="_blank" rel="noreferrer">{short(record.vault)} ↗ View in explorer</a>
            <label className="field-label vault-deposit-label" htmlFor="deposit">Deposit BNB (confirm in your connected wallet)</label>
            <div className="vault-deposit">
              <input id="deposit" className="vault-input" value={depositValue} onChange={(e) => setDepositValue(e.target.value)} inputMode="decimal" />
              <button className="button" onClick={() => void (wallet ? runDeposit() : handleConnect())} disabled={!!busy}>{wallet ? 'Deposit' : 'Connect wallet'}</button>
            </div>
            <div className="timing-list vault-facts">
              <div><span>Key epoch (increases with each rotation)</span><strong className="mono">{dashboard ? String(dashboard.epoch) : '—'}</strong></div>
              <div><span>Next signature index / lane capacity</span><strong className="mono">{dashboard ? `${dashboard.laneNext} / 65536` : '—'}</strong></div>
              <div><span>Remaining key rotations (256 total)</span><strong className="mono">{dashboard ? String(256n - dashboard.recNonce) : '—'}</strong></div>
            </div>
            <div className="vault-reset">
              <button className="text-button" onClick={() => void refreshDashboard()}>Refresh on-chain state</button>
              <button className="text-button" onClick={() => setCreateOpen(true)} disabled={!factory}>Create another vault</button>
              <button className="text-button" onClick={exitVault}>Close vault</button>
              {!keyLoaded && <button className="text-button" onClick={() => setImportOpen((v) => !v)}>Import backup</button>}
            </div>
          </section>

          <section className="panel vault-execute">
            <div className="section-title"><h2>Transfer / contract call</h2>{preview && <span className="result-badge success">Digest verified</span>}</div>
            <p className="panel-description">Preview compares local and on-chain state without spending gas or consuming a signature index. Review the result before confirming execution. Each signing attempt permanently reserves a signature index.</p>
            <label className="field-label" htmlFor="to">Recipient / target address<span className="mono">Starts with 0x</span></label>
            <input id="to" className="vault-input" value={execTo} onChange={(e) => { setExecTo(e.target.value); setPreview(null); }} placeholder="0x…" spellCheck={false} />
            <label className="field-label" htmlFor="value">BNB amount<span className="mono">Use 0 for a call with no BNB value</span></label>
            <input id="value" className="vault-input" value={execValue} onChange={(e) => { setExecValue(e.target.value); setPreview(null); }} inputMode="decimal" />
            <label className="field-label"><span>Advanced: contract calldata (for token transfers, etc.)</span>
              <button className="text-button" onClick={() => setExecAdvanced((v) => !v)}>{execAdvanced ? 'Collapse' : 'Expand'}</button></label>
            {execAdvanced && <textarea value={execData} onChange={(e) => { setExecData(e.target.value); setPreview(null); }} rows={3} placeholder="0x… (for example, an encoded token transfer)" spellCheck={false} />}
            <div className="vault-execute-actions">
              <button className="button" onClick={() => void runPreview()} disabled={!!busy || !execTo.trim()}>Preview</button>
              <button className="button button-primary" onClick={() => void runExecute()} disabled={!!busy || !execTo.trim() || !keyLoaded || !!record.pendingRecovery || !!record.pendingDeployment}>{preview ? `Confirm execution (index ${preview.idx})` : 'Execute'}</button>
            </div>
            {preview && <p className="subtle-copy">Signature index <span className="mono">{preview.idx}</span> ({preview.method === 'executeFirst' ? 'first signature in a subtree: approximately 4,928 bytes' : 'cached subtree: approximately 2,464 bytes'}).</p>}
            {!keyLoaded && <p className="vault-warn">Import your backup to load the key. If signing history is missing, preserve the original browser and recovery records, and verify the history before rotating keys.</p>}
          </section>

          <section className="panel vault-recover">
            <div className="section-title"><h2>Rotate keys (recovery)</h2><span className="result-badge failure">SENSITIVE OPERATION</span></div>
            <p className="panel-description">Generate an independent replacement backup. Once confirmed on-chain, the old backup can no longer control the vault. Save and verify the new backup before submitting. The vault supports up to 256 rotations.</p>
            <p className="subtle-copy">Each recovery index can authorize only one replacement key. Keep the original browser and recovery records. Do not sign again if you are unsure whether that recovery signature was generated on another device.</p>
            {!record.pendingRecovery && !recoveryDraft && <button className="button" onClick={() => void startRecovery()} disabled={!!busy || !keyLoaded}>Generate recovery backup</button>}
            {recoveryDraft && !record.pendingRecovery && <>
              <button className="button" onClick={downloadRecoveryBackup}>Download new backup</button>
              <label className="field-label" htmlFor="recovery-check">Verify the new backup code</label>
              <textarea id="recovery-check" value={recoveryCheck} onChange={e => setRecoveryCheck(e.target.value)} rows={3} spellCheck={false} />
            </>}
            {(recoveryDraft || record.pendingRecovery) && <>
              <label className="vault-check"><input type="checkbox" checked={recoverConfirm} onChange={(e) => setRecoverConfirm(e.target.checked)} /><span>I saved the new backup offline and understand the old backup becomes invalid after confirmation.</span></label>
              <button className="button vault-danger" onClick={() => void (wallet ? doRecover() : handleConnect())} disabled={!!busy || !recoverConfirm || (!!record.pendingRecovery?.submissionUncertain && !record.pendingRecovery?.hash)}>{record.pendingRecovery ? 'Check this key rotation' : 'Confirm key rotation'}</button>
              {record.pendingRecovery && <p className="subtle-copy">This recovery plan is fixed. Keep the new backup. Refresh on-chain state to check the outcome; this does not automatically resend the transaction.</p>}
              {record.pendingRecovery?.submissionUncertain && !record.pendingRecovery.hash && <>
                <label className="field-label" htmlFor="recovery-tx">If the wallet sent the transaction but the result is unknown, paste its recovery transaction hash.</label>
                <input id="recovery-tx" className="vault-input" value={recoveryTxHash} onChange={e => setRecoveryTxHash(e.target.value)} placeholder="0x…" />
                <button className="button" disabled={!!busy} onClick={() => void run('Checking wallet transaction…', async () => {
                  await vault.attachRecoveryTransaction(record, recoveryTxHash.trim() as Hex);
                  await refreshDashboard();
                })}>Verify transaction and restore record</button>
              </>}
            </>}
          </section>

          <section className="panel vault-history">
            <div className="section-title"><h2>Transaction history</h2><span className="mono">ON-CHAIN RECORDS</span></div>
            {record.txs.length === 0 ? <p className="subtle-copy">No transactions recorded.</p> : (
              <ul className="vault-txlist">
                {[...record.txs].reverse().map((tx) => (
                  <li key={tx.hash}><span>{tx.label}{tx.status ? ` · ${tx.status === 'pending' ? 'Pending' : tx.status === 'reverted' ? 'Reverted' : 'Confirmed'}` : ''}</span>
                    <a className="mono" href={vault.explorerTx(chainId, tx.hash)} target="_blank" rel="noreferrer">{short(tx.hash)} ↗</a>
                  </li>
                ))}
              </ul>
            )}
            <div className="vault-reset">
              <button className="text-button" onClick={() => setImportOpen((v) => !v)}>{importOpen ? 'Close import' : 'Import backup / use another key'}</button>
              {keyLoaded && <button className="text-button" onClick={() => void doLock()} disabled={!!busy}>Lock key</button>}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
