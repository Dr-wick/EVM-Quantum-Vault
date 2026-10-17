// SPDX-License-Identifier: MIT
/**
 * Thin vault state readers over an injected viem PublicClient.
 * Shared by the browser app and scripts/demo.ts (Node passes its own client),
 * so this file must stay free of vite-only imports.
 */
import type { Address, Hex, PublicClient } from 'viem';
import { VAULT_ABI } from './ops';

export interface VaultGlobals { epoch: bigint; recNonce: bigint }
export interface VaultKeyState extends VaultGlobals { root: Hex; recRoot: Hex; pkSeed: Hex }

export async function readVaultKey(client: PublicClient, vault: Address): Promise<VaultKeyState> {
  const blockNumber = await client.getBlockNumber();
  const names = ['epoch', 'recNonce', 'root', 'recRoot', 'pkSeed'] as const;
  const values = await Promise.all(names.map(functionName => client.readContract({ address: vault, abi: VAULT_ABI, functionName, blockNumber })));
  return { epoch: values[0] as bigint, recNonce: values[1] as bigint, root: values[2] as Hex, recRoot: values[3] as Hex, pkSeed: values[4] as Hex };
}
export interface LaneState { nextIdx: bigint; nonce: bigint }

export async function readVaultGlobals(client: PublicClient, vault: Address): Promise<VaultGlobals> {
  const [epoch, recNonce] = await Promise.all([
    client.readContract({ address: vault, abi: VAULT_ABI, functionName: 'epoch' }),
    client.readContract({ address: vault, abi: VAULT_ABI, functionName: 'recNonce' }),
  ]);
  return { epoch: epoch as bigint, recNonce: recNonce as bigint };
}

export async function readLane(client: PublicClient, vault: Address, lane: number): Promise<LaneState> {
  const [nextIdx, nonce] = await Promise.all([
    client.readContract({ address: vault, abi: VAULT_ABI, functionName: 'nextIdx', args: [lane] }),
    client.readContract({ address: vault, abi: VAULT_ABI, functionName: 'nonce', args: [lane] }),
  ]);
  return { nextIdx: nextIdx as bigint, nonce: nonce as bigint };
}

export async function readNeedsTopLayer(client: PublicClient, vault: Address, idx: number): Promise<boolean> {
  return await client.readContract({ address: vault, abi: VAULT_ABI, functionName: 'needsTopLayerAt', args: [BigInt(idx)] }) as boolean;
}

export async function readDigestAt(
  client: PublicClient, vault: Address, idx: number, target: Address, value: bigint, data: Hex,
): Promise<Hex> {
  return await client.readContract({ address: vault, abi: VAULT_ABI, functionName: 'digestAt', args: [BigInt(idx), target, value, data] }) as Hex;
}

const ERC20_MIN_ABI = [{
  type: 'function', name: 'balanceOf', stateMutability: 'view',
  inputs: [{ name: 'a', type: 'address' }], outputs: [{ type: 'uint256' }],
}] as const;

export async function readErc20Balance(client: PublicClient, token: Address, owner: Address): Promise<bigint> {
  return await client.readContract({ address: token, abi: ERC20_MIN_ABI, functionName: 'balanceOf', args: [owner] }) as bigint;
}
