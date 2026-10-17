import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { VM } from '@ethereumjs/vm';
import { Common, Hardfork } from '@ethereumjs/common';
import { Address, Account, hexToBytes, bytesToHex } from '@ethereumjs/util';
import { encodeFunctionData, decodeFunctionResult, encodeAbiParameters, concatHex, getContractAddress, keccak256, type Abi, type Hex } from 'viem';
import artifacts from '../src/generated/contracts.json';
import { fastCchs } from '../src/crypto/fast.ts';
import { deriveAccountKey } from '../src/crypto/derive.ts';
import { toHex, toAbiLayerSig, signatureBytes, type CchsKey, type Tree } from '../src/crypto/cchs.ts';

const relayer = Address.fromString('0x1000000000000000000000000000000000000001');
const recipient = Address.fromString('0x2000000000000000000000000000000000000002');
const other = Address.fromString('0x3000000000000000000000000000000000000003');
const fabi = artifacts.factory.abi as Abi, vabi = artifacts.vault.abi as Abi;
const zeros16 = `0x${'00'.repeat(16)}` as Hex;
const oneRoot = `0x${'01'.repeat(32)}` as Hex;
const oneSeed = `0x${'01'.repeat(16)}` as Hex;
const encode = (abi: Abi, functionName: string, args: readonly unknown[] = []) => hexToBytes(encodeFunctionData({ abi, functionName, args }));
const decode = (abi: Abi, functionName: string, ret: Uint8Array) => decodeFunctionResult({ abi, functionName, data: bytesToHex(ret) as Hex });

async function setup(chainId = 97) {
  const common = Common.custom({ chainId, networkId: chainId, name: `test-${chainId}` }, { hardfork: Hardfork.Cancun });
  const vm = await VM.create({ common });
  await vm.stateManager.putAccount(relayer, new Account(0n, 10n ** 24n));
  const send = async (to: Address | undefined, data: Uint8Array, value = 0n) => {
    const result = await vm.evm.runCall({ caller: relayer, to, data, gasLimit: 30_000_000n, value });
    return { ok: !result.execResult.exceptionError, ret: result.execResult.returnValue, created: result.createdAddress, gas: result.execResult.executionGasUsed, error: result.execResult.exceptionError?.error };
  };
  return { vm, send };
}

test('factory and direct vault deployment allow only BSC, reject zero seeds, and expose no admin', async () => {
  const constructor = encodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes16' }], [oneRoot, oneRoot, oneSeed]);
  for (const chainId of [1, 56, 97]) {
    const { send } = await setup(chainId);
    const factory = await send(undefined, hexToBytes(artifacts.factory.bytecode as Hex));
    const direct = await send(undefined, hexToBytes(concatHex([artifacts.vault.bytecode as Hex, constructor])));
    assert.equal(factory.ok, chainId !== 1, `factory deployment on ${chainId}`);
    assert.equal(direct.ok, chainId !== 1, `direct vault deployment on ${chainId}`);
    if (factory.created && factory.ok) {
      assert.equal((await send(factory.created, encode(fabi, 'deploy', [oneRoot, oneRoot, zeros16]))).ok, false);
      assert.equal((await send(factory.created, encode(fabi, 'deploy', [`0x${'00'.repeat(32)}`, oneRoot, oneSeed]))).ok, false);
      assert.equal((await send(factory.created, encode(fabi, 'deploy', [oneRoot, `0x${'00'.repeat(32)}`, oneSeed]))).ok, false);
    }
  }
  const { send } = await setup();
  const invalid = encodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes16' }], [oneRoot, oneRoot, zeros16]);
  assert.equal((await send(undefined, hexToBytes(concatHex([artifacts.vault.bytecode as Hex, invalid])))).ok, false);
  const functions = [...fabi, ...vabi].filter((item) => item.type === 'function').map((item) => item.name);
  for (const name of ['owner', 'admin', 'upgradeTo', 'initialize', 'deployAndMove']) assert.equal(functions.includes(name), false, name);
  assert.ok(artifacts.vault.runtimeBytes < 24_576);
  assert.ok(artifacts.factory.runtimeBytes < 24_576);
});

test('BSC 97: client signatures execute first/cached BNB and token calls, reject tampering/replay, and recover', { timeout: 180_000 }, async () => {
  const { vm, send } = await setup();
  const deployed = await send(undefined, hexToBytes(artifacts.factory.bytecode as Hex));
  assert.equal(deployed.ok, true, deployed.error);
  const factory = deployed.created!;
  assert.equal(keccak256(bytesToHex(await vm.stateManager.getContractCode(factory)) as Hex), artifacts.factory.runtimeHash);
  const c = await fastCchs();
  const seed = new Uint8Array(32).fill(0x42); // Public synthetic test entropy only.
  const scope = { chainId: 97 as const, factory: factory.toString() as Hex, deploymentNamespace: 'bqv-evm-test/v1', accountIndex: 0n, epoch: 0n };
  let key = deriveAccountKey(seed, scope);
  let trees = new Map<string, Tree>();
  let pub = c.keygen(key, trees);
  const roots = [toHex(pub.root), toHex(pub.recRoot), toHex(pub.seed)] as const;
  const params = [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes16' }] as const;
  const args = encodeAbiParameters(params, roots);
  const offline = getContractAddress({ opcode: 'CREATE2', from: factory.toString() as Hex, salt: keccak256(args), bytecode: concatHex([artifacts.vault.bytecode as Hex, args]) });
  const predicted = await send(factory, encode(fabi, 'predict', roots));
  assert.equal((decode(fabi, 'predict', predicted.ret) as string).toLowerCase(), offline.toLowerCase());
  const create = await send(factory, encode(fabi, 'deploy', roots), 5n * 10n ** 18n);
  assert.equal(create.ok, true, create.error);
  const vault = Address.fromString(decode(fabi, 'deploy', create.ret) as string);
  assert.equal(vault.toString(), offline.toLowerCase());
  const again = await send(factory, encode(fabi, 'deploy', roots));
  assert.equal(decode(fabi, 'deploy', again.ret), decode(fabi, 'deploy', create.ret));
  const balance = async (address: Address) => (await vm.stateManager.getAccount(address))?.balance ?? 0n;
  assert.equal(await balance(vault), 5n * 10n ** 18n);
  const view = async (name: string, values: readonly unknown[] = []) => {
    const result = await send(vault, encode(vabi, name, values));
    assert.equal(result.ok, true, `${name}: ${result.error}`);
    return decode(vabi, name, result.ret);
  };
  const metrics: Record<string, string> = { factoryExecutionGas: String(deployed.gas), createVaultExecutionGas: String(create.gas) };
  async function prepare(idx: number, target = recipient, value = 10n ** 16n, data: Hex = '0x', signingKey: CchsKey = key, cache = trees) {
    const nonce = BigInt(await view('nonce', [idx >> 16]) as bigint);
    const needsTop = await view('needsTopLayerAt', [BigInt(idx)]) as boolean;
    const digest = c.executeDigest({ chainId: 97n, account: vault.bytes, nonce, idx: BigInt(idx), target: target.bytes, value, dataHash: hexToBytes(keccak256(data)) });
    assert.equal(toHex(digest), await view('digestAt', [BigInt(idx), target.toString(), value, data]));
    const sig = c.sign(signingKey, idx, digest, !needsTop, cache);
    const method = sig.l1 ? 'executeFirst' : 'execute';
    const callArgs = [target.toString(), value, data, BigInt(idx), toAbiLayerSig(sig.l0), ...(sig.l1 ? [toAbiLayerSig(sig.l1)] : [])];
    return { sig, method, callArgs, data: encode(vabi, method, callArgs) };
  }
  const first = await prepare(0);
  assert.equal(signatureBytes(first.sig), 4928);
  const sent = await send(vault, first.data);
  assert.equal(sent.ok, true, sent.error);
  metrics.firstExecutionGas = String(sent.gas);
  assert.equal(await balance(recipient), 10n ** 16n);
  assert.equal((await send(vault, first.data)).ok, false, 'replayed first signature');

  const cached = await prepare(1);
  assert.equal(signatureBytes(cached.sig), 2464);
  const movedTarget = [...cached.callArgs]; movedTarget[0] = other.toString();
  assert.equal((await send(vault, encode(vabi, cached.method, movedTarget))).ok, false, 'front-run target change');
  const damaged = structuredClone(cached.sig); damaged.l0.wots[0][0] ^= 1;
  const damagedArgs = [...cached.callArgs]; damagedArgs[4] = toAbiLayerSig(damaged.l0);
  assert.equal((await send(vault, encode(vabi, cached.method, damagedArgs))).ok, false, 'tampered chain value');
  const cachedResult = await send(vault, cached.data);
  assert.equal(cachedResult.ok, true, cachedResult.error);
  metrics.cachedExecutionGas = String(cachedResult.gas);

  // A small ERC-20-like token demonstrates that the vault actually forwards
  // the signed calldata with itself as caller, rather than only moving BNB.
  const solc = createRequire(import.meta.url)('solc') as { compile(input: string): string };
  const tokenOutput = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity', sources: { 'Token.sol': { content: 'pragma solidity ^0.8.28; contract Token { mapping(address=>uint256) public balanceOf; function mint(address a,uint256 n) external {balanceOf[a]+=n;} function transfer(address a,uint256 n) external returns(bool){require(balanceOf[msg.sender]>=n);balanceOf[msg.sender]-=n;balanceOf[a]+=n;return true;} }' } }, settings: { evmVersion: 'cancun', outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } })));
  const tokenArtifact = tokenOutput.contracts['Token.sol'].Token as { abi: Abi; evm: { bytecode: { object: string } } };
  const tokenDeploy = await send(undefined, hexToBytes(`0x${tokenArtifact.evm.bytecode.object}`));
  assert.equal(tokenDeploy.ok, true); const token = tokenDeploy.created!;
  assert.equal((await send(token, encode(tokenArtifact.abi, 'mint', [vault.toString(), 1000n]))).ok, true);
  const tokenData = bytesToHex(encode(tokenArtifact.abi, 'transfer', [recipient.toString(), 250n])) as Hex;
  const tokenSpend = await prepare(2, token, 0n, tokenData);
  assert.equal((await send(vault, tokenSpend.data)).ok, true);
  const tokenBalance = await send(token, encode(tokenArtifact.abi, 'balanceOf', [recipient.toString()]));
  assert.equal(decode(tokenArtifact.abi, 'balanceOf', tokenBalance.ret), 250n);

  const skip = await prepare(9); assert.equal((await send(vault, skip.data)).ok, true);
  assert.equal(await view('nextIdx', [0]), 10n);
  const jump = await prepare(1024);
  assert.ok(jump.sig.l1);
  assert.equal((await send(vault, encode(vabi, 'execute', jump.callArgs.slice(0, 5)))).ok, false, 'uncached path without proof');
  assert.equal((await send(vault, jump.data)).ok, true);
  const lane0Next = await view('nextIdx', [0]);
  const lane1 = await prepare(65_536);
  assert.equal((await send(vault, lane1.data)).ok, true);
  assert.equal(await view('nextIdx', [0]), lane0Next, 'lane 1 must not move lane 0');
  assert.equal(await view('nextIdx', [1]), 65_537n);

  const nextKey = deriveAccountKey(new Uint8Array(32).fill(0x73), { ...scope, epoch: 1n });
  const leakedBackupNext = deriveAccountKey(seed, { ...scope, epoch: 1n });
  assert.notDeepEqual(nextKey.master, leakedBackupNext.master, 'old backup cannot derive the replacement seed');
  const nextTrees = new Map<string, Tree>();
  const nextPub = c.keygen(nextKey, nextTrees);
  const oldUnused = await prepare(2048); // A signed but unsubmitted old-epoch operation.
  const recNonce = BigInt(await view('recNonce') as bigint);
  const recoveryMessage = c.recoveryDigest({ chainId: 97n, account: vault.bytes, recNonce, newRoot: nextPub.root, newRecRoot: nextPub.recRoot, newSeed: nextPub.seed });
  const recovery = c.signRecovery(key, Number(recNonce), recoveryMessage, trees);
  const recoverArgs = [toHex(nextPub.root), toHex(nextPub.recRoot), toHex(nextPub.seed), recovery.wots.map(toHex), recovery.auth.map(toHex)];
  const zeroRecovery = [...recoverArgs]; zeroRecovery[2] = zeros16;
  assert.equal((await send(vault, encode(vabi, 'recover', zeroRecovery))).ok, false, 'zero new public seed');
  const recoveryData = encode(vabi, 'recover', recoverArgs);
  const recovered = await send(vault, recoveryData);
  assert.equal(recovered.ok, true, recovered.error);
  metrics.recoveryExecutionGas = String(recovered.gas);
  assert.equal(await view('epoch'), 1n);
  assert.equal(await view('nextIdx', [0]), 0n);
  assert.equal(await view('nextIdx', [1]), 65_536n);
  assert.equal(await view('nonce', [1]), 0n);
  assert.equal((await send(vault, oldUnused.data)).ok, false, 'old root accepted after rotation');
  assert.equal((await send(vault, recoveryData)).ok, false, 'recovery replay');
  key = nextKey; trees = nextTrees; pub = nextPub;
  const finalSpend = await prepare(0, recipient, await balance(vault));
  assert.equal((await send(vault, finalSpend.data)).ok, true);
  assert.equal(await balance(vault), 0n);
  console.log('BSC testnet-ID EVM checks passed (execution gas excludes tx intrinsic/calldata):', metrics);
});
