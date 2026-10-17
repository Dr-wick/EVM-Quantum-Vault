// Dry run by default. Broadcasting requires --broadcast. Mainnet additionally
// requires --chain 56 and --allow-mainnet. Never invoke this from the UI.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPublicClient, createWalletClient, http, keccak256, formatEther, getContractAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { bsc, bscTestnet } from 'viem/chains';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

async function main() {
  const args = process.argv.slice(2);
  const flags = new Set();
  let chainId = 97;
  let selectedChain = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--chain') {
      if (selectedChain || !['56', '97'].includes(args[i + 1])) throw new Error('Specify --chain once with 56 or 97.');
      selectedChain = true; chainId = Number(args[++i]);
    } else if (['--broadcast', '--allow-mainnet', '--help'].includes(args[i])) flags.add(args[i]);
    else throw new Error('Unknown flag; use --help.');
  }
  if (flags.has('--help')) {
    console.log('node scripts/deploy.mjs [--chain 97|56] [--broadcast] [--allow-mainnet]\nDefault: BSC testnet dry run. Chain 56 also requires --allow-mainnet. RPC_URL overrides the public RPC. DEPLOYER_PRIVATE_KEY is read only from the environment.');
    return;
  }
  if (chainId === 56 && !flags.has('--allow-mainnet')) throw new Error('Chain 56 requires the explicit --allow-mainnet flag.');
  if (chainId === 97 && flags.has('--allow-mainnet')) throw new Error('--allow-mainnet is only valid with --chain 56.');
  const chain = chainId === 56 ? bsc : bscTestnet;
  const artifact = JSON.parse(readFileSync(resolve(root, 'src/generated/contracts.json'), 'utf8'));
  if (artifact.format !== 'bqv-artifact-v1') throw new Error('Unrecognized artifact; run npm run compile.');
  console.log(`${flags.has('--broadcast') ? 'Broadcast requested' : 'Dry run'}: ${chain.name} (${chain.id}); factory runtime hash ${artifact.factory.runtimeHash}`);
  const privateKey = process.env.DEPLOYER_PRIVATE_KEY;
  if (!privateKey) {
    if (flags.has('--broadcast')) throw new Error('DEPLOYER_PRIVATE_KEY is required for broadcasting.');
    console.log('No deployer configured. Artifact inspected; no RPC call or transaction sent.');
    return;
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) throw new Error('DEPLOYER_PRIVATE_KEY must be a 32-byte hex key.');
  const account = privateKeyToAccount(privateKey);
  const transport = http(process.env.RPC_URL || chain.rpcUrls.default.http[0]);
  const publicClient = createPublicClient({ chain, transport });
  if (await publicClient.getChainId() !== chain.id) throw new Error('RPC chain ID differs from the selected BSC network.');
  const [nonce, balance, gas, gasPrice] = await Promise.all([
    publicClient.getTransactionCount({ address: account.address, blockTag: 'pending' }),
    publicClient.getBalance({ address: account.address }),
    publicClient.estimateGas({ account, data: artifact.factory.bytecode }),
    publicClient.getGasPrice(),
  ]);
  const gasLimit = (gas * 120n + 99n) / 100n;
  const predicted = getContractAddress({ from: account.address, nonce: BigInt(nonce) });
  console.log(`Deployer ${account.address}; predicted factory ${predicted}; gas cap ${gasLimit}; estimated cap ${formatEther(gasLimit * gasPrice)} ${chain.nativeCurrency.symbol}.`);
  if (!flags.has('--broadcast')) { console.log('Dry run complete. No transaction was signed or sent.'); return; }
  if (balance < gasLimit * gasPrice) throw new Error('Deployer balance cannot cover the estimated gas cap.');
  const wallet = createWalletClient({ chain, transport, account });
  const hash = await wallet.deployContract({ abi: artifact.factory.abi, bytecode: artifact.factory.bytecode, gas: gasLimit, gasPrice, nonce });
  // Save public pending evidence immediately, so an interrupted receipt wait is recoverable.
  mkdirSync(resolve(root, 'deployments'), { recursive: true });
  const path = resolve(root, 'deployments', `${chain.id}-${hash}.json`);
  const record = { chainId: chain.id, deployer: account.address, factory: predicted, transactionHash: hash, runtimeHash: artifact.factory.runtimeHash, compiler: artifact.compiler, status: 'pending' };
  writeFileSync(path, `${JSON.stringify(record, null, 2)}\n`);
  console.log(`Transaction ${hash}. Public deployment record saved.`);
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== 'success' || receipt.contractAddress?.toLowerCase() !== predicted.toLowerCase()) throw new Error('Deployment receipt failed or returned an unexpected address; inspect the saved public record.');
  const code = await publicClient.getCode({ address: predicted });
  if (!code || keccak256(code) !== artifact.factory.runtimeHash) throw new Error('Deployed runtime does not match the compiled artifact.');
  writeFileSync(path, `${JSON.stringify({ ...record, status: 'verified-runtime', blockNumber: String(receipt.blockNumber), gasUsed: String(receipt.gasUsed) }, null, 2)}\n`);
  console.log(`Factory deployed and bytecode checked: ${predicted}`);
}

main().catch((error) => {
  // Do not print the original error object: RPC errors can carry signed payloads
  // and credential-bearing URLs. Only locally constructed, bounded messages.
  const message = error?.shortMessage ? 'RPC request failed; no secret-bearing error details printed.' : String(error?.message ?? 'Deployment failed.');
  const key = process.env.DEPLOYER_PRIVATE_KEY;
  console.error(key ? message.split(key).join('[redacted]') : message);
  process.exitCode = 1;
});
