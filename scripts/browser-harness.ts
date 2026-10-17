/** Local browser acceptance fixture. All chain state is an in-memory EVM. No live RPC or private keys. */
import { createServer as createHttpServer } from 'node:http';
import { createServer as createViteServer } from 'vite';
import { VM } from '@ethereumjs/vm';
import { Common, Hardfork } from '@ethereumjs/common';
import { Address, Account, bytesToHex, hexToBytes } from '@ethereumjs/util';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const artifacts = JSON.parse(readFileSync(resolve(root, 'src/generated/contracts.json'), 'utf8'));
const build = JSON.parse(readFileSync(resolve(root, 'artifacts/build-info.json'), 'utf8'));
const vm = await VM.create({ common: Common.custom({ chainId: 56, networkId: 56 }, { hardfork: Hardfork.Cancun }) });
const sender = Address.fromString('0x1000000000000000000000000000000000000001');
const factory = Address.fromString('0x4000000000000000000000000000000000000004');
await vm.stateManager.putAccount(sender, new Account(0n, 10n ** 24n));
await vm.stateManager.putAccount(factory, new Account());
await vm.stateManager.putContractCode(factory, hexToBytes(`0x${build.output.contracts['contracts/BscQuantumVaultFactory.sol'].BscQuantumVaultFactory.evm.deployedBytecode.object}`));
let block = 1n, queue = Promise.resolve();
const receipts = new Map<string, object>(), transactions = new Map<string, object>();
const hex = (n: bigint) => `0x${n.toString(16)}`;
const blockHash = () => `0x${block.toString(16).padStart(64, '0')}`;

async function rpc(method: string, params: any[]): Promise<unknown> {
  if (method === 'eth_chainId') return '0x38';
  if (method === 'eth_blockNumber') return hex(block);
  if (method === 'eth_gasPrice') return '0x3b9aca00';
  if (method === 'eth_getTransactionCount') return '0x0';
  if (method === 'eth_getBalance') return hex((await vm.stateManager.getAccount(Address.fromString(params[0])))?.balance ?? 0n);
  if (method === 'eth_getCode') return bytesToHex(await vm.stateManager.getContractCode(Address.fromString(params[0])));
  if (method === 'eth_getTransactionReceipt') return receipts.get(params[0]) ?? null;
  if (method === 'eth_getTransactionByHash') return transactions.get(params[0]) ?? null;
  if (method === 'eth_getBlockByNumber') return { number: hex(block), hash: blockHash(), timestamp: '0x65000000', gasLimit: '0x1c9c380', gasUsed: '0x0', baseFeePerGas: '0x0', transactions: [] };
  if (['eth_call', 'eth_estimateGas', 'eth_sendTransaction'].includes(method)) {
    const tx = params[0];
    const write = method === 'eth_sendTransaction';
    if (write && tx.from?.toLowerCase() !== sender.toString()) throw new Error('Fixture sender only');
    await vm.stateManager.checkpoint();
    const result = await vm.evm.runCall({ caller: tx.from ? Address.fromString(tx.from) : sender,
      to: tx.to ? Address.fromString(tx.to) : undefined, data: hexToBytes(tx.data ?? '0x'), value: BigInt(tx.value ?? 0), gasLimit: 30_000_000n });
    if (!write) {
      await vm.stateManager.revert();
      if (result.execResult.exceptionError) throw new Error('Local EVM reverted');
      return method === 'eth_call' ? bytesToHex(result.execResult.returnValue) : hex(result.execResult.executionGasUsed + 150_000n);
    }
    await vm.stateManager.commit(); block++;
    const hash = blockHash();
    receipts.set(hash, { transactionHash: hash, transactionIndex: '0x0', blockHash: hash, blockNumber: hex(block),
      from: sender.toString(), to: tx.to, contractAddress: result.createdAddress?.toString() ?? null,
      gasUsed: hex(result.execResult.executionGasUsed + 21000n), cumulativeGasUsed: '0x100000', effectiveGasPrice: '0x3b9aca00',
      status: result.execResult.exceptionError ? '0x0' : '0x1', type: '0x0', logs: [], logsBloom: `0x${'00'.repeat(256)}` });
    transactions.set(hash, { ...tx, input: tx.data ?? '0x', value: tx.value ?? '0x0', hash, blockHash: hash, blockNumber: hex(block),
      transactionIndex: '0x0', nonce: '0x0', gas: '0x1c9c380', gasPrice: '0x3b9aca00', type: '0x0', v: '0x25', r: '0x1', s: '0x1' });
    return hash;
  }
  throw new Error(`Unsupported local fixture method ${method}`);
}

const server = createHttpServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Headers', 'content-type');
  if (req.method === 'OPTIONS') { res.end(); return; }
  let body = ''; for await (const chunk of req) body += chunk;
  const input = JSON.parse(body);
  const handle = async (q: any) => {
    try { return { jsonrpc: '2.0', id: q.id, result: await rpc(q.method, q.params ?? []) }; }
    catch { return { jsonrpc: '2.0', id: q.id, error: { code: -32000, message: 'Local fixture request failed' } }; }
  };
  const task = queue.then(async () => {
    const result = Array.isArray(input) ? await Promise.all(input.map(handle)) : await handle(input);
    res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(result));
  });
  queue = task.catch(() => { res.statusCode = 500; res.end(); });
});
await new Promise<void>(r => server.listen(8547, '127.0.0.1', r));
const endpoint = 'http://127.0.0.1:8547';
const vite = await createViteServer({ root, server: { host: '127.0.0.1', port: 5175, strictPort: true },
  define: {
    'import.meta.env.VITE_BSC_MAINNET_RPC': JSON.stringify(endpoint),
    'import.meta.env.VITE_BSC_TESTNET_RPC': JSON.stringify(endpoint),
    'import.meta.env.VITE_BSC_MAINNET_FACTORY': JSON.stringify(factory.toString()),
    'import.meta.env.VITE_BSC_TESTNET_FACTORY': JSON.stringify(''),
  },
  plugins: [{ name: 'local-chain-fixture', transformIndexHtml() { return [
    { tag: 'script', injectTo: 'head-prepend', children: `window.ethereum={request:async({method,params})=>{if(method==='eth_requestAccounts')return ['${sender}'];if(method==='wallet_switchEthereumChain')return null;const r=await fetch('${endpoint}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});const j=await r.json();if(j.error)throw new Error(j.error.message);return j.result}};` },
    { tag: 'div', injectTo: 'body-prepend', attrs: { style: 'background:#f7d774;color:#222;text-align:center;padding:8px' }, children: 'Local simulated chain · No real assets · No mainnet connection' },
  ]; } }],
});
await vite.listen();
console.log('Local EVM fixture: http://127.0.0.1:5175 (no live network)');
async function close() { await vite.close(); server.close(); process.exit(0); }
process.on('SIGINT', () => void close()); process.on('SIGTERM', () => void close());
