import { useEffect, useRef, useState, type ReactNode } from 'react';
import { NETWORKS, readNetworkStatus } from './services';
import { FACTORY } from './vault/ops';
import { HELP_FAQ, HELP_STEPS } from './help';
import VaultPage from './VaultPage';

type Page = 'overview' | 'vault' | 'help';
type ChainId = 56 | 97;
type NetworkStatus = Awaited<ReturnType<typeof readNetworkStatus>>;

function Icon({ name, size = 20 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    overview: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
    vault: <><rect x="3" y="4" width="18" height="15" rx="2" /><circle cx="12" cy="11.5" r="3.6" /><path d="M12 15.1v2.4M7.5 8v7M16.5 8v7" /></>,
    arrow: <path d="M5 12h14m-5-5 5 5-5 5" />,
    shield: <><path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z" /><path d="m8 12 3 3 5-6" /></>,
    wallet: <><path d="M21 8H5a2 2 0 0 1 0-4h13v4M5 8H3v12h18V8ZM16 12h5v5h-5a2.5 2.5 0 0 1 0-5Z" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    info: <><circle cx="12" cy="12" r="9" /><path d="M12 11v6M12 7h.01" /></>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] || paths.info}</svg>;
}

function VaultIllustration() {
  return <div className="vault-illustration" aria-hidden="true">
    <svg viewBox="0 0 390 320" fill="none">
      <defs>
        <pattern id="grid" width="24" height="24" patternUnits="userSpaceOnUse"><path d="M24 0H0V24" stroke="#d6d2c9" strokeWidth=".6" /></pattern>
        <linearGradient id="vaultFace" x1="105" y1="83" x2="276" y2="244" gradientUnits="userSpaceOnUse"><stop stopColor="#faf8f1" /><stop offset="1" stopColor="#e9e4d8" /></linearGradient>
      </defs>
      <rect x="17" y="17" width="354" height="285" fill="url(#grid)" opacity=".5" />
      <circle cx="197" cy="155" r="124" stroke="#bdb7aa" strokeDasharray="3 7" />
      <ellipse cx="209" cy="272" rx="108" ry="12" fill="#ddd7ca" opacity=".6" />
      <path d="m95 76 147-25 59 41-151 26-55-42Z" fill="#f8f5e9" stroke="#a9a28f" />
      <path d="m242 51 59 41v155l-59-44V51Z" fill="#bcb5a5" stroke="#77715f" />
      <path d="m95 76 147 24v155L95 231V76Z" fill="url(#vaultFace)" stroke="#77715f" strokeWidth="1.3" />
      <path d="m242 100 59-8v155l-59 8V100Z" fill="#d7ceba" stroke="#77715f" strokeWidth="1.3" />
      <path d="m112 95 112 19v120l-112-18V95Z" fill="#eeeadf" stroke="#a9a28f" />
      <path d="m123 106 90 15v101l-90-15V106Z" stroke="#c3bba8" />
      <path d="m227 119 10 2v19l-10-2v-19ZM227 201l10 2v19l-10-2v-19Z" fill="#98917f" />
      <ellipse cx="169" cy="163" rx="35" ry="39" transform="rotate(-9 169 163)" fill="#272b27" stroke="#0f1712" strokeWidth="1.5" />
      <ellipse cx="169" cy="163" rx="27" ry="30" transform="rotate(-9 169 163)" stroke="#555c51" />
      <path d="m169 135 1 10m-23 3 8 6m-9 22 10-6m18 20-2-10m22-5-11-7m9-20-10 6" stroke="#d3d0b9" strokeWidth="2" />
      <ellipse cx="169" cy="163" rx="13" ry="15" transform="rotate(-9 169 163)" fill="#edb84c" stroke="#f3d179" />
      <path d="m168 156 6 7-4 6-6-7 4-6Z" fill="#252a23" />
      <path d="M60 82h17M68.5 73.5v17M320 233h17M328.5 224.5v17" stroke="#9b9788" />
      <path d="M259 49h54v37M67 222v39h41" stroke="#b6af9f" />
      <circle cx="314" cy="88" r="4" fill="#d8a32c" />
      <circle cx="111" cy="261" r="4" fill="#d8a32c" />
    </svg>
    <div className="illustration-label mono">YOUR ASSETS. YOUR VAULT.</div>
  </div>;
}

export default function App() {
  const [page, setPage] = useState<Page>('overview');
  const [chainId, setChainId] = useState<ChainId>(56);
  const [network, setNetwork] = useState<NetworkStatus | null>(null);
  const [networkError, setNetworkError] = useState('');
  const [networkBusy, setNetworkBusy] = useState(true);
  const [networkRefresh, setNetworkRefresh] = useState(0);
  const heading = useRef<HTMLHeadingElement>(null);
  const net = NETWORKS[chainId];
  const canCreate = Boolean(FACTORY[chainId]);

  useEffect(() => {
    let active = true;
    setNetwork(null); setNetworkError(''); setNetworkBusy(true);
    readNetworkStatus(chainId).then(value => { if (active) setNetwork(value); })
      .catch(error => { if (active) setNetworkError(error instanceof Error ? error.message : 'Unable to read network data'); })
      .finally(() => { if (active) setNetworkBusy(false); });
    return () => { active = false; };
  }, [chainId, networkRefresh]);

  function navigate(next: Page) {
    setPage(next);
    requestAnimationFrame(() => heading.current?.focus());
  }
  const navigation: { id: Page; label: string; icon: string; number: string }[] = [
    { id: 'overview', label: 'Overview', icon: 'overview', number: '01' },
    { id: 'vault', label: 'My vault', icon: 'vault', number: '02' },
    { id: 'help', label: 'Help', icon: 'info', number: '03' },
  ];
  const titles = {
    overview: { title: 'Your assets. Your vault.', description: 'Create an independent vault on BSC. Keep your backup and authorize every transfer.' },
    vault: { title: 'My vault', description: 'Create or open a vault, view its balance, deposit assets, and authorize transfers.' },
    help: { title: 'A guide to your first vault.', description: 'Learn how wallets and vaults differ, and how to back up, transfer assets, and rotate keys.' },
  };

  return <div className="app-shell">
    <a className="skip-link" href="#main">Skip to content</a>
    <aside className="sidebar">
      <button className="brand" onClick={() => navigate('overview')} aria-label="EVM Quantum Vault home">
        <span className="brand-mark"><svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><path d="m16 3 12 7v12l-12 7-12-7V10L16 3Z" stroke="currentColor" strokeWidth="1.5" /><path d="m16 9 6 3.5v7L16 23l-6-3.5v-7L16 9Z" fill="currentColor" /><path d="m13 14 3 1.8 3-1.8v4L16 20l-3-2v-4Z" fill="#232921" /></svg></span>
        <span>EQV<span className="brand-sub">EVM QUANTUM VAULT</span></span>
      </button>
      <div className="sidebar-label">PERSONAL VAULTS</div>
      <nav className="main-nav" aria-label="Main navigation">{navigation.map(item => <button key={item.id} className={page === item.id ? 'nav-item active' : 'nav-item'} onClick={() => navigate(item.id)} aria-label={item.label} title={item.label} aria-current={page === item.id ? 'page' : undefined}><Icon name={item.icon} /><span>{item.label}</span><span className="nav-number mono">{item.number}</span></button>)}</nav>
      <div className="sidebar-bottom"><div className="sidebar-note"><Icon name="shield" size={14} />Your backup. Your authorization.</div><p>Each vault is independently created and managed.</p><a className="source-link" href="https://github.com/Dr-wick/EVM-Quantum-Vault" target="_blank" rel="noreferrer">Source &amp; documentation<Icon name="arrow" size={14} /></a></div>
    </aside>
    <div className="main-shell">
      <header className="topbar">
        <div className="breadcrumb">EQV<span>/</span><strong>{navigation.find(item => item.id === page)?.label}</strong></div>
        <div className="topbar-actions">
          <label className="network-select"><span className={`status-dot ${chainId === 56 ? 'mainnet' : ''}`} /><span className="sr-only">Select a BSC network</span><select value={chainId} onChange={event => setChainId(Number(event.target.value) as ChainId)}><option value={56}>BSC Mainnet</option><option value={97}>BSC Testnet</option></select></label>
          <button className="button button-wallet" onClick={() => navigate(page === 'vault' ? 'help' : 'vault')}><Icon name={page === 'vault' ? 'info' : 'vault'} size={17} />{page === 'vault' ? 'Help' : 'Open vault'}</button>
        </div>
      </header>
      <main id="main" className="main-content">
        <div className="page-heading"><div><h1 ref={heading} tabIndex={-1}>{titles[page].title}</h1><p>{titles[page].description}</p></div></div>
        {page === 'overview' && <>
          <section className="hero-card">
            <div className="hero-copy"><div className="small-tag"><span className="tag-square" />EVM QUANTUM VAULT</div><h2>A dedicated home<br />for your assets<span>.</span></h2><p>Connect a wallet and create your vault.<br />Keep the backup. Authorize your transfers.</p>
              <div className="hero-actions"><button className="button button-primary" onClick={() => navigate('vault')}>Get started<Icon name="arrow" size={18} /></button><button className="text-button" onClick={() => navigate('help')}>Read the guide</button></div>
              <div className="hero-footnote"><Icon name="wallet" size={14} />Your wallet pays gas. Your vault holds assets.</div>
            </div><VaultIllustration />
          </section>
          <section className="overview-features" aria-label="How the vault works">
            <article className="panel"><Icon name="vault" /><h2>An independent vault address</h2><p>Each vault stores assets at its own on-chain address.</p></article>
            <article className="panel"><Icon name="shield" /><h2>Keep your own backup</h2><p>Your vault backup authorizes transfers. The application cannot hold, recover, or reset it for you.</p></article>
            <article className="panel"><Icon name="check" /><h2>Review every operation</h2><p>Check the recipient before sending and inspect the transaction afterward. Pending, confirmed, and reverted outcomes are shown separately.</p></article>
          </section>
          <section className="panel overview-start"><div><h2>Before you create your first vault</h2><p>Prepare a wallet with BNB for gas and a safe offline location for your vault backup.</p><button className="text-button" onClick={() => navigate('help')}>Learn about creation and backups<Icon name="arrow" size={16} /></button></div>
            <div className="network-summary"><span className="field-label">SELECTED NETWORK</span><strong>{net.name}</strong><p>{canCreate ? 'Vault creation available' : 'Vault creation is not configured'} · {networkBusy ? 'Reading network' : network ? 'Connected to network' : 'Network unavailable'}</p></div>
          </section>
          <div className="scope-note"><Icon name="info" size={17} /><p>This version has not been independently audited. Protect your backup and device; hash-based signatures do not eliminate network, device, or user-error risks.</p></div>
        </>}
        {page === 'vault' && <VaultPage chainId={chainId} onHelp={() => navigate('help')} />}
        {page === 'help' && <div className="help-layout">
          <div className="help-main">
            <section className="panel help-steps" aria-labelledby="help-steps-title"><div className="section-title"><h2 id="help-steps-title">Getting started</h2><span className="soft-badge">START HERE</span></div>
              <ol>{HELP_STEPS.map((step, index) => <li id={`help-${step.id}`} key={step.id}><span className="step-number mono">0{index + 1}</span><div><h3>{step.title}</h3><p>{step.text}</p><p className="help-step-note">{step.note}</p></div></li>)}</ol>
              <button className="button button-primary" onClick={() => navigate('vault')}>Open my vault<Icon name="arrow" size={17} /></button>
            </section>
            <section className="panel help-faq" aria-labelledby="help-faq-title"><h2 id="help-faq-title">Frequently asked questions</h2>{HELP_FAQ.map(item => <details key={item.question}><summary>{item.question}</summary><p>{item.answer}</p></details>)}</section>
          </div>
          <aside className="help-aside">
            <section className="panel help-note"><Icon name="shield" size={23} /><h2>Understand the two keys</h2><dl><div><dt>Connected wallet</dt><dd>Your existing wallet connects to the app and pays gas. You never need to give its private key to the application.</dd></div><div><dt>Vault backup code</dt><dd>Independent key material generated locally for your vault. Anyone who holds it can authorize the use of vault assets.</dd></div></dl></section>
            <section className="panel help-note"><Icon name="info" size={23} /><h2>Check pending transactions first</h2><p>Keep your backup and operation records. Check the on-chain outcome before proceeding. A network timeout does not mean a transaction was never sent.</p></section>
          </aside>
        </div>}
        <footer className="page-footer"><span>EVM Quantum Vault<span className="footer-dot">·</span>Personal on-chain vaults</span><div><span className={`status-dot ${networkError ? 'unavailable' : ''}`} />{networkBusy ? 'Reading network' : network ? <a href={`${net.explorer}/block/${network.blockNumber.replaceAll(',', '')}`} target="_blank" rel="noreferrer">Block <span className="mono">#{network.blockNumber}</span></a> : <button className="footer-retry" onClick={() => setNetworkRefresh(value => value + 1)} title={networkError}>Unable to read network data · Retry</button>}</div></footer>
      </main>
    </div>
  </div>;
}
