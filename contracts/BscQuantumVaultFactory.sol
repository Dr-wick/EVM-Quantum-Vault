// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BscQuantumVault} from "./BscQuantumVault.sol";

/// @title BscQuantumVaultFactory — permissionless BSC vault creation.
/// @notice No administrator, fee, upgrade path, or token-pulling operation.
contract BscQuantumVaultFactory {
    mapping(bytes32 => address) public vaultOf;

    event VaultDeployed(address indexed vault, bytes32 indexed root, bytes16 seed);
    error UnsupportedChain(uint256 chainId);
    error ZeroRoot();
    error ZeroSeed();
    error FundingFailed();

    constructor() {
        _requireBsc();
    }

    /// @notice Create or return a vault; any BNB supplied is forwarded to it.
    /// @dev Public keys must come from a factory-specific account KDF. The
    ///      factory cannot detect reuse of a secret tree under another factory.
    function deploy(bytes32 root, bytes32 recRoot, bytes16 seed)
        external payable returns (address vault)
    {
        _requireBsc();
        if (root == bytes32(0) || recRoot == bytes32(0)) revert ZeroRoot();
        if (seed == bytes16(0)) revert ZeroSeed();
        bytes32 salt = keccak256(abi.encode(root, recRoot, seed));
        vault = vaultOf[salt];
        if (vault == address(0)) {
            vault = address(new BscQuantumVault{salt: salt}(root, recRoot, seed));
            vaultOf[salt] = vault;
            emit VaultDeployed(vault, root, seed);
        }
        if (msg.value != 0) {
            (bool ok,) = vault.call{value: msg.value}("");
            if (!ok) revert FundingFailed();
        }
    }

    function predict(bytes32 root, bytes32 recRoot, bytes16 seed)
        external view returns (address)
    {
        bytes32 salt = keccak256(abi.encode(root, recRoot, seed));
        bytes32 initCodeHash = keccak256(abi.encodePacked(
            type(BscQuantumVault).creationCode, abi.encode(root, recRoot, seed)
        ));
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt, initCodeHash
        )))));
    }

    function _requireBsc() internal view {
        if (block.chainid != 56 && block.chainid != 97) revert UnsupportedChain(block.chainid);
    }
}
