// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BscQuantumVaultBase} from "./BscQuantumVaultBase.sol";

/// @title BscQuantumVault — CCHS-K-20 verification for BSC (56/97).
/// @notice An immutable vault with no owner, administrator or upgrade function.
/// @dev Keccak256 verification inherited from Aegis Protocol (MIT); see NOTICE.
contract BscQuantumVault is BscQuantumVaultBase {
    string public constant VERSION = "bqv-k-20/1.0.0";

    constructor(bytes32 _root, bytes32 _recRoot, bytes16 _seed) {
        _init(_root, _recRoot, _seed);
    }

    function _hash(bytes memory data) internal pure override returns (bytes32) {
        return keccak256(data);
    }

    function _wotsLeaf(
        uint256 seed,
        uint8 layer,
        uint64 treeIdx,
        uint32 leafIdx,
        bytes32 m,
        bytes32[67] calldata sig
    ) internal pure override returns (bytes32 leaf) {
        uint8[67] memory digits = _digits(m);
        bytes32 base = _adrs(seed, layer, treeIdx, 0x00, leafIdx, 0, 0);
        bytes32 leafAdrs = _adrs(seed, layer, treeIdx, 0x01, leafIdx, 0, 0);

        assembly {
            let buf := mload(0x40)
            mstore(0x40, add(buf, 2176))
            mstore(buf, leafAdrs)

            for { let c := 0 } lt(c, 67) { c := add(c, 1) } {
                let x := calldataload(add(sig, mul(c, 32)))
                let adrsC := or(base, shl(136, c))
                let start := mload(add(digits, mul(c, 32)))
                for { let s := start } lt(s, 15) { s := add(s, 1) } {
                    mstore(0x00, or(adrsC, shl(128, s)))
                    mstore(0x20, x)
                    x := keccak256(0x00, 64)
                }
                mstore(add(buf, add(32, mul(c, 32))), x)
            }

            leaf := keccak256(buf, 2176)
        }
    }

    function _node(bytes32 adrs, bytes32 cur, bytes32 sib, uint256 odd)
        internal pure override returns (bytes32 out)
    {
        assembly {
            let p := mload(0x40)
            mstore(p, adrs)
            switch odd
            case 0 { mstore(add(p, 32), cur) mstore(add(p, 64), sib) }
            default { mstore(add(p, 32), sib) mstore(add(p, 64), cur) }
            out := keccak256(p, 96)
        }
    }
}
