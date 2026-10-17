import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeFunctionData, encodeErrorResult, hexToBytes } from 'viem';
import { cchsK, eq, toHex } from '../src/crypto/cchs';
import {
  VAULT_ABI, decodeSeedWithChecksum, encodeExecuteCall, encodeRecoverCall, encodeSeedWithChecksum,
  executeDigestFor, parseSeedBackup, predictVaultAddress, recoveryDigestFor, scopeFor, seedBackupFile, vaultErrorName,
  type SeedBackupPublic,
} from '../src/vault/ops';

test('seed codec: roundtrip, whitespace/case tolerance, checksum and format errors', () => {
  const seed = new Uint8Array(32).fill(7);
  const encoded = encodeSeedWithChecksum(seed);
  assert.match(encoded, /^0x[0-9a-f]{72}$/);
  assert.equal(encodeSeedWithChecksum(seed), encoded); // deterministic
  assert.ok(eq(decodeSeedWithChecksum(encoded), seed));
  assert.ok(eq(decodeSeedWithChecksum(`  ${encoded.slice(0, 40)} ${encoded.slice(40).toUpperCase()}  `), seed));
  const flipped = `${encoded.slice(0, -1)}${encoded.endsWith('f') ? '0' : 'f'}`;
  assert.throws(() => decodeSeedWithChecksum(flipped), /checksum/);
  assert.throws(() => decodeSeedWithChecksum('0x1234'), /format/);
  assert.throws(() => encodeSeedWithChecksum(new Uint8Array(16)), /32 bytes/);
});

test('seed backup file: roundtrip with public fields, raw-hex fallback, shape rejection', () => {
  const seed = new Uint8Array(32).fill(9);
  const publicFields: SeedBackupPublic = {
    namespace: 'bqv-web/v1', accountIndex: '0', epoch: '0',
    root: `0x${'11'.repeat(32)}`, recRoot: `0x${'22'.repeat(32)}`, pkSeed: `0x${'33'.repeat(16)}`,
    factory: '0x4000000000000000000000000000000000000004', vault: `0x${'44'.repeat(20)}`,
  };
  const parsed = parseSeedBackup(JSON.stringify(seedBackupFile(seed, publicFields)));
  assert.ok(eq(parsed.seed, seed));
  assert.deepEqual(parsed.publicFields, publicFields);
  const raw = parseSeedBackup(encodeSeedWithChecksum(seed));
  assert.ok(eq(raw.seed, seed));
  assert.equal(raw.publicFields, undefined);
  assert.throws(() => parseSeedBackup('{"format":"nope","seed":"0x00"}'), /Unrecognized/);
  assert.throws(() => parseSeedBackup('{broken'), /JSON/);
});

test('execute calldata roundtrips through the vault ABI for both entry points', () => {
  const wots = Array.from({ length: 67 }, (_, i) => new Uint8Array(32).fill(i & 0xff));
  const auth = Array.from({ length: 10 }, (_, i) => new Uint8Array(32).fill(0x80 + i));
  const l0 = { wots, auth };
  const target = '0x2000000000000000000000000000000000000002' as const;
  const data = '0xdeadbeef' as const;

  const cached = encodeExecuteCall(5, target, 123_456n, data, { l0, idx: 5 });
  const decodedCached = decodeFunctionData({ abi: VAULT_ABI, data: cached });
  assert.equal(decodedCached.functionName, 'execute');
  const cachedArgs = decodedCached.args as readonly unknown[];
  assert.equal(String(cachedArgs[0]).toLowerCase(), target);
  assert.equal(cachedArgs[1], 123_456n);
  assert.equal(cachedArgs[2], data);
  assert.equal(cachedArgs[3], 5n);
  assert.equal((cachedArgs[4] as { wots: string[]; auth: string[] }).wots.length, 67);
  assert.equal((cachedArgs[4] as { wots: string[]; auth: string[] }).auth.length, 10);
  assert.equal((cachedArgs[4] as { wots: string[] }).wots[7].toLowerCase(), toHex(wots[7]));

  const first = encodeExecuteCall(5, target, 0n, '0x', { l0, l1: { wots, auth }, idx: 5 });
  const decodedFirst = decodeFunctionData({ abi: VAULT_ABI, data: first });
  assert.equal(decodedFirst.functionName, 'executeFirst');
  assert.equal((decodedFirst.args as readonly unknown[]).length, 6);
});

test('recover calldata roundtrips through the vault ABI', () => {
  const wots = Array.from({ length: 67 }, () => new Uint8Array(32).fill(0x11));
  const auth = Array.from({ length: 8 }, () => new Uint8Array(32).fill(0x22));
  const newRoot = `0x${'aa'.repeat(32)}` as const;
  const newRecRoot = `0x${'bb'.repeat(32)}` as const;
  const newPkSeed = `0x${'cc'.repeat(16)}` as const;
  const decoded = decodeFunctionData({ abi: VAULT_ABI, data: encodeRecoverCall(newRoot, newRecRoot, newPkSeed, { wots, auth }) });
  assert.equal(decoded.functionName, 'recover');
  const args = decoded.args as readonly unknown[];
  assert.equal(args[0], newRoot);
  assert.equal(args[1], newRecRoot);
  assert.equal(args[2], newPkSeed);
  assert.equal((args[3] as string[]).length, 67);
  assert.equal((args[4] as string[]).length, 8);
});

test('digest helpers match the crypto core exactly and reject non-BSC chains', () => {
  const vault = '0x1000000000000000000000000000000000000001' as const;
  const target = '0x2000000000000000000000000000000000000002' as const;
  const data = '0x1234' as const;
  const viaHelper = executeDigestFor(cchsK, { chainId: 97, vault, laneNonce: 3n, idx: 7, target, value: 10n ** 16n, data });
  const direct = cchsK.executeDigest({
    chainId: 97n, account: hexToBytes(vault), nonce: 3n, idx: 7n,
    target: hexToBytes(target), value: 10n ** 16n, dataHash: cchsK.hash(hexToBytes(data)),
  });
  assert.ok(eq(viaHelper, direct));

  const recoveryParams = {
    chainId: 56 as const, vault, recNonce: 1n,
    newRoot: `0x${'11'.repeat(32)}` as const, newRecRoot: `0x${'22'.repeat(32)}` as const, newPkSeed: `0x${'33'.repeat(16)}` as const,
  };
  const recHelper = recoveryDigestFor(cchsK, recoveryParams);
  const recDirect = cchsK.recoveryDigest({
    chainId: 56n, account: hexToBytes(vault), recNonce: 1n,
    newRoot: hexToBytes(recoveryParams.newRoot), newRecRoot: hexToBytes(recoveryParams.newRecRoot), newSeed: hexToBytes(recoveryParams.newPkSeed),
  });
  assert.ok(eq(recHelper, recDirect));

  assert.throws(() => executeDigestFor(cchsK, { chainId: 1 as 97, vault, laneNonce: 0n, idx: 0, target, value: 0n, data: '0x' }));
});

test('vaultErrorName decodes custom errors from viem-shaped failures', () => {
  const data = encodeErrorResult({ abi: VAULT_ABI, errorName: 'IndexUsed' } as never);
  assert.equal(vaultErrorName({ data }), 'IndexUsed');
  const nested = encodeErrorResult({ abi: VAULT_ABI, errorName: 'BadTopRoot' } as never);
  assert.equal(vaultErrorName({ cause: { data: nested } }), 'BadTopRoot');
  assert.equal(vaultErrorName(new Error('boom')), null);
});

test('scope and CREATE2 prediction are deterministic and input-sensitive', () => {
  const factory = '0x4000000000000000000000000000000000000004' as const;
  const root = `0x${'11'.repeat(32)}` as const;
  const recRoot = `0x${'22'.repeat(32)}` as const;
  const pkSeed = `0x${'33'.repeat(16)}` as const;
  const predicted = predictVaultAddress(factory, root, recRoot, pkSeed);
  assert.equal(predicted, predictVaultAddress(factory, root, recRoot, pkSeed));
  assert.notEqual(predicted, predictVaultAddress(factory, recRoot, root, pkSeed));
  assert.equal(scopeFor(56, factory, 0).chainId, 56);
  assert.equal(scopeFor(56, factory, 0).epoch, 0n);
  assert.notEqual(scopeFor(56, factory, 0).chainId, scopeFor(97, factory, 0).chainId);
  assert.equal(scopeFor(56, factory, 2).epoch, 2n);
});
