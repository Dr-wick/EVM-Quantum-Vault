import { createPublicClient, formatEther, formatGwei, getAddress, http, type Address, type Hex, type TransactionReceipt } from 'viem';
import { bsc, bscTestnet } from 'viem/chains';
export const NETWORKS = {
  97: { name: 'BSC Testnet', symbol: 'tBNB', explorer: 'https://testnet.bscscan.com' },
  56: { name: 'BSC Mainnet', symbol: 'BNB', explorer: 'https://bscscan.com' },
} as const;
type ChainId = keyof typeof NETWORKS;
function checkChain(chainId: number): asserts chainId is ChainId {
  if (chainId !== 56 && chainId !== 97) throw new Error('This application supports BSC mainnet and testnet only.');
}
export function getPublicClient(chainId: number) {
  checkChain(chainId);
  const chain = chainId === 97 ? bscTestnet : bsc;
  const url = chainId === 97
    ? import.meta.env.VITE_BSC_TESTNET_RPC || 'https://bsc-testnet-dataseed.bnbchain.org'
    : import.meta.env.VITE_BSC_MAINNET_RPC || 'https://bsc-dataseed.bnbchain.org';
  return createPublicClient({ chain, transport: http(url, { timeout: 10_000, retryCount: 1 }) });
}

export async function readNetworkStatus(chainId: number): Promise<{ blockNumber: string; gasGwei: string }> {
  const rpc = getPublicClient(chainId);
  try {
    const [actualChain, block, gas] = await Promise.all([rpc.getChainId(), rpc.getBlockNumber(), rpc.getGasPrice()]);
    if (actualChain !== chainId) throw new Error('RPC network mismatch.');
    return { blockNumber: block.toLocaleString('en-US'), gasGwei: formatGwei(gas) };
  } catch { throw new Error('Network data is temporarily unavailable. Try again later. A failed read does not mean the balance is zero.'); }
}

interface Provider { request(args: { method: string; params?: unknown[] }): Promise<unknown> }
function injected(): Provider {
  const provider = (window as Window & { ethereum?: Provider }).ethereum;
  if (!provider) throw new Error('No wallet extension was detected. Open this page in a browser with a wallet such as MetaMask or Rabby, or install an extension and reload.');
  return provider;
}
export async function connectWallet(chainId: number): Promise<{ address: string; balance: string; chainId: number }> {
  checkChain(chainId);
  const provider = injected();
  let account: Address;
  try {
    const result = await provider.request({ method: 'eth_requestAccounts' });
    if (!Array.isArray(result) || typeof result[0] !== 'string') throw new Error('No wallet address was returned.');
    account = getAddress(result[0]);
  } catch (error) {
    if ((error as { code?: number }).code === 4001) throw new Error('Wallet connection canceled.');
    throw new Error('Unable to read the wallet address. Check the connection request in your wallet.');
  }
  const rpc = getPublicClient(chainId);
  try {
    const [actualChain, balance] = await Promise.all([rpc.getChainId(), rpc.getBalance({ address: account })]);
    if (actualChain !== chainId) throw new Error('RPC network mismatch');
    return { address: account, balance: formatEther(balance), chainId };
  } catch { throw new Error('The wallet address was received, but the node could not read its balance. Try again later.'); }
}

// ---------------------------------------------------- wallet write channel

/** Ask the wallet to switch to a supported BSC network (56 / 97). */
export async function ensureWalletChain(chainId: number): Promise<void> {
  checkChain(chainId);
  const provider = injected();
  try {
    await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: `0x${chainId.toString(16)}` }] });
  } catch (error) {
    if ((error as { code?: number }).code === 4001) throw new Error('Network switch canceled. Select the corresponding BSC network in your wallet to operate the vault.');
    throw new Error('Switch your wallet to the selected BSC mainnet or testnet network and try again.');
  }
}

/** Send a transaction through the connected wallet; gas is paid by that account. */
export async function sendTransaction(params: { from: string; to: string; data?: Hex; value?: bigint }): Promise<Hex> {
  const provider = injected();
  const tx: Record<string, string> = { from: params.from, to: params.to };
  if (params.data) tx.data = params.data;
  if (params.value && params.value > 0n) tx.value = `0x${params.value.toString(16)}`;
  try {
    const hash = await provider.request({ method: 'eth_sendTransaction', params: [tx] });
    if (typeof hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error('wallet did not return a transaction hash');
    return hash as Hex;
  } catch (error) {
    if ((error as { code?: number }).code === 4001) throw Object.assign(new Error('You canceled this transaction in your wallet.'), { code: 4001 });
    throw new Error('The wallet could not send the transaction. Check the network and balance before retrying; do not manually resend the same calldata from your wallet.');
  }
}

/** Wait for a receipt; null on timeout or an uncertain read — callers must NOT auto-resend. */
export async function waitForReceipt(chainId: number, hash: Hex, timeoutMs = 90_000): Promise<TransactionReceipt | null> {
  const rpc = getPublicClient(chainId);
  try { return await rpc.waitForTransactionReceipt({ hash, timeout: timeoutMs, pollingInterval: 3_000 }); }
  catch { return null; }
}
