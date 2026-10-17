import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import solc from 'solc';
import { keccak256 } from 'viem';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const names = ['BscQuantumVaultBase', 'BscQuantumVault', 'BscQuantumVaultFactory'];

export function compile() {
  if (!solc.version().startsWith('0.8.37+')) throw new Error('Use the pinned solc 0.8.37 compiler.');
  const sources = Object.fromEntries(names.map((name) => [`contracts/${name}.sol`, {
    content: readFileSync(resolve(root, 'contracts', `${name}.sol`), 'utf8'),
  }]));
  const input = {
    language: 'Solidity', sources,
    settings: {
      optimizer: { enabled: true, runs: 1_000_000 }, viaIR: true,
      evmVersion: 'cancun', metadata: { bytecodeHash: 'none', appendCBOR: false },
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object'] } },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  for (const entry of output.errors ?? []) console.error(entry.formattedMessage);
  if (output.errors?.some((entry) => entry.severity === 'error')) throw new Error('Contract compilation failed.');
  const artifact = (name) => {
    const c = output.contracts[`contracts/${name}.sol`][name];
    const runtime = `0x${c.evm.deployedBytecode.object}`;
    return { abi: c.abi, bytecode: `0x${c.evm.bytecode.object}`, runtimeHash: keccak256(runtime), runtimeBytes: (runtime.length - 2) / 2 };
  };
  const contracts = {
    format: 'bqv-artifact-v1', compiler: solc.version(),
    factory: artifact('BscQuantumVaultFactory'), vault: artifact('BscQuantumVault'),
  };
  mkdirSync(resolve(root, 'src/generated'), { recursive: true });
  mkdirSync(resolve(root, 'artifacts'), { recursive: true });
  writeFileSync(resolve(root, 'src/generated/contracts.json'), `${JSON.stringify(contracts, null, 2)}\n`);
  writeFileSync(resolve(root, 'artifacts/build-info.json'), `${JSON.stringify({ compiler: solc.version(), input, output }, null, 2)}\n`);
  console.log(`Compiled EVM Quantum Vault (BSC 56/97): ${contracts.vault.runtimeBytes} runtime bytes; factory: ${contracts.factory.runtimeBytes} bytes.`);
  return contracts;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) compile();
