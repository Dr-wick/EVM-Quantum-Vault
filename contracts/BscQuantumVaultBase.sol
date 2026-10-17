// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title BscQuantumVaultBase — BSC-only CCHS-K-20 vault state machine.
/// @notice WOTS+ signatures (w=16, 67 chains), two tree layers of height 10,
///         cached subtrees, 16 independent index lanes and hash-based recovery.
/// @dev Derived from Aegis Protocol, commit 71e4070ff7ce56a23e66a2bf742ace889868aa50.
///      A signature leaf must never sign two distinct messages. The client must
///      persist index reservations BEFORE signing and use isolated account keys.
///      The contracts prevent a second accepted use, but cannot see an unpublished
///      signature. This implementation is experimental and has not been audited.
abstract contract BscQuantumVaultBase {
    // ---------------------------------------------------------------- params
    uint256 internal constant W      = 16;
    uint256 internal constant LEN    = 67;   // 64 message + 3 checksum chains
    uint256 internal constant H      = 10;   // tree height per layer
    uint256 internal constant LEAVES = 1 << H;
    uint256 internal constant REC_H  = 8;
    /// @notice 2^LANE_BITS lanes of 2^(2H - LANE_BITS) leaves each (16 × 65 536).
    uint256 public  constant LANE_BITS  = 4;
    uint256 internal constant LANE_SHIFT = 2 * H - LANE_BITS;

    // --------------------------------------------------------------- storage
    /// @notice Top-layer tree root. Rotatable only via `recover`.
    bytes32 public root;
    /// @notice Recovery tree root (single layer, height 8).
    bytes32 public recRoot;
    /// @notice Epoch increments on every recovery; namespaces `cachedRoot` and the lanes.
    uint64  public epoch;
    /// @notice Next unused recovery leaf in [0, 256).
    uint64  public recNonce;
    /// @notice Public seed of the current key tree, carried in the last 16 bytes
    ///         of every ADRS. It makes each hash call of this tree a different
    ///         function from the same position in any other tree (another
    ///         account, chain or epoch), which the multi-target security
    ///         argument needs (spec §2.2, §5.5). Packed with `epoch` and
    ///         `recNonce` in one slot, so reading it costs nothing extra.
    bytes16 public pkSeed;

    /// @dev key = (epoch << 64) | bottomTreeIdx
    mapping(uint256 => bytes32) public cachedRoot;

    /// @dev key = (epoch << 8) | lane; value = nonce << 64 | nextIdx (absolute leaf index).
    ///      A fresh (epoch, lane) slot is zero, which reads as nextIdx = first
    ///      leaf of the lane and nonce = 0.
    mapping(uint256 => uint256) internal _lane;

    // ---------------------------------------------------------------- types
    struct LayerSig {
        bytes32[67] wots;   // one chain value per WOTS+ chain
        bytes32[10] auth;   // Merkle authentication path, leaf → root
    }

    // --------------------------------------------------------------- events
    event Executed(uint64 indexed idx, address indexed target, uint256 value);
    event SubtreeCached(uint64 indexed epoch, uint64 indexed treeIdx, bytes32 subtreeRoot);
    event Recovered(uint64 indexed newEpoch, bytes32 newRoot, bytes32 newRecRoot, bytes16 newSeed);

    // --------------------------------------------------------------- errors
    error Exhausted();
    error IndexUsed();
    error BadSubtreeRoot();
    error MissingTopLayer();
    error BadTopRoot();
    error BadRecovery();
    error CallFailed();
    error ZeroRoot();
    error ZeroSeed();
    error UnsupportedChain(uint256 chainId);
    error AlreadyInitialized();

    // --------------------------------------------------------------- init
    /// @dev Constructor-only initialization; there is no external initializer.
    function _init(bytes32 _root, bytes32 _recRoot, bytes16 _seed) internal {
        if (block.chainid != 56 && block.chainid != 97) revert UnsupportedChain(block.chainid);
        if (root != bytes32(0)) revert AlreadyInitialized();
        if (_root == bytes32(0) || _recRoot == bytes32(0)) revert ZeroRoot();
        if (_seed == bytes16(0)) revert ZeroSeed();
        root    = _root;
        recRoot = _recRoot;
        pkSeed  = _seed;
    }

    receive() external payable {}

    // BNB arrives through receive(); BEP-20 tokens arrive through transfer().

    // ============================================================ hash hooks

    /// @dev Generic hash of a memory buffer (digests, recovery messages).
    function _hash(bytes memory data) internal view virtual returns (bytes32);

    /// @dev From a WOTS+ signature on `m`, complete every chain to its end and
    ///      compress the 67 chain ends into the leaf hash. Hot path. `seed` is
    ///      the tree's public seed as the low 128 bits of a word.
    function _wotsLeaf(
        uint256 seed,
        uint8 layer,
        uint64 treeIdx,
        uint32 leafIdx,
        bytes32 m,
        bytes32[67] calldata sig
    ) internal view virtual returns (bytes32 leaf);

    /// @dev Merkle node hash with child order chosen by `odd` (position parity).
    function _node(bytes32 adrs, bytes32 cur, bytes32 sib, uint256 odd)
        internal view virtual returns (bytes32 out);

    // ============================================================= execute

    /// @notice Execute `target.call{value}(data)` authorized by a CCHS signature.
    /// @param idx    Leaf index the signer chose. Must be `>= nextIdx`; indices
    ///               below `idx` are abandoned forever (`nextIdx` becomes
    ///               `idx + 1`). Skipping is how a signer leaves behind a leaf
    ///               whose signature was broadcast but never landed, or an
    ///               entire subtree whose keys it no longer trusts. Only the
    ///               signer can skip, because `idx` is bound into the digest.
    /// @param l0     Bottom-layer WOTS+ signature + auth path for leaf `idx`.
    /// @dev   Cached path: the subtree of `idx` must already be registered.
    ///        Carrying only one layer keeps calldata at 2.5 KB; use
    ///        `executeFirst` for the first operation in a subtree.
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint64 idx,
        LayerSig calldata l0
    ) external returns (bytes memory result) {
        bytes32 m = _begin(idx, target, value, data);
        bytes32 r0 = _layerRoot(0, idx >> H, uint32(idx & (LEAVES - 1)), m, l0);
        bytes32 cached = cachedRoot[_cacheKey(idx >> H)];
        if (cached == bytes32(0)) revert MissingTopLayer();
        if (cached != r0) revert BadSubtreeRoot();
        return _finish(idx, target, value, data);
    }

    /// @notice `execute` with the top-layer proof for the subtree of `idx`.
    ///         Registers the subtree root (once) and runs the call. If the
    ///         subtree is already registered the proof is ignored, so a
    ///         transaction prepared before another registration landed still
    ///         succeeds.
    /// @param l1     Top-layer WOTS+ signature on the bottom subtree root + auth path.
    function executeFirst(
        address target,
        uint256 value,
        bytes calldata data,
        uint64 idx,
        LayerSig calldata l0,
        LayerSig calldata l1
    ) external returns (bytes memory result) {
        bytes32 m = _begin(idx, target, value, data);
        uint64 treeIdx = idx >> H;
        bytes32 r0 = _layerRoot(0, treeIdx, uint32(idx & (LEAVES - 1)), m, l0);
        uint256 key = _cacheKey(treeIdx);
        bytes32 cached = cachedRoot[key];
        if (cached != bytes32(0)) {
            if (cached != r0) revert BadSubtreeRoot();
        } else {
            // Top layer: tree 0, leaf = treeIdx, message = r0.
            if (_layerRoot(1, 0, uint32(treeIdx), r0, l1) != root) revert BadTopRoot();
            cachedRoot[key] = r0;
            emit SubtreeCached(epoch, treeIdx, r0);
        }
        return _finish(idx, target, value, data);
    }

    /// @dev Index discipline shared by both entry points, then the digest.
    ///      The lane is the top LANE_BITS bits of `idx`; `idx` must not be below
    ///      the lane's `nextIdx`, and the digest binds the lane's nonce.
    function _begin(uint64 idx, address target, uint256 value, bytes calldata data)
        internal view returns (bytes32)
    {
        if (idx >= (1 << (2 * H))) revert Exhausted();
        uint256 s = _lane[_laneKey(idx)];
        if (idx < uint64(s)) revert IndexUsed();
        return _digest(uint64(s >> 64), idx, target, value, data);
    }

    /// @dev State update (effects) then the call (interaction).
    function _finish(uint64 idx, address target, uint256 value, bytes calldata data)
        internal returns (bytes memory result)
    {
        uint256 k = _laneKey(idx);
        unchecked {
            uint256 s = _lane[k];
            _lane[k] = (((s >> 64) + 1) << 64) | uint256(idx + 1);
        }
        bool ok;
        (ok, result) = target.call{value: value}(data);
        if (!ok) revert CallFailed();
        emit Executed(idx, target, value);
    }

    // ============================================================ recovery

    /// @notice Rotate the public key (`root`, `recRoot`, `pkSeed`), authorized
    ///         by the recovery tree of the current epoch. Bumps `epoch`, which
    ///         opens fresh lanes (every `nextIdx` back to the start of its lane,
    ///         every nonce 0) and logically clears the cache.
    function recover(
        bytes32 newRoot,
        bytes32 newRecRoot,
        bytes16 newSeed,
        bytes32[67] calldata wots,
        bytes32[8]  calldata auth
    ) external {
        if (newRoot == bytes32(0) || newRecRoot == bytes32(0)) revert ZeroRoot();
        if (newSeed == bytes16(0)) revert ZeroSeed();
        uint64 rn = recNonce;
        if (rn >= (1 << REC_H)) revert Exhausted();

        bytes32 m = _hash(
            abi.encodePacked(
                "BQV_RECOVER_V1",
                block.chainid,
                address(this),
                rn,
                newRoot,
                newRecRoot,
                newSeed
            )
        );

        // layer id 0xFF marks the recovery tree in ADRS; the tree was built with the current seed.
        uint256 seed = uint256(uint128(pkSeed));
        bytes32 r = _wotsLeaf(seed, 0xFF, 0, uint32(rn), m, wots);
        uint32 pos = uint32(rn);
        for (uint256 k = 0; k < REC_H; ++k) {
            r = _node(_adrs(seed, 0xFF, 0, 0x02, uint32(pos >> 1), uint8(k), 0), r, auth[k], pos & 1);
            pos >>= 1;
        }
        if (r != recRoot) revert BadRecovery();

        root    = newRoot;
        recRoot = newRecRoot;
        pkSeed  = newSeed;
        unchecked {
            epoch    += 1;
            recNonce  = rn + 1;
        }
        emit Recovered(epoch, newRoot, newRecRoot, newSeed);
    }

    // ============================================================ internals

    /// @dev M = hash("BQV_EXECUTE_V1" ‖ chainId ‖ this ‖ nonce ‖ idx ‖ target ‖ value ‖ keccak256(data)),
    ///      `nonce` being the nonce of the lane of `idx`.
    function _digest(uint64 laneNonce, uint64 idx, address target, uint256 value, bytes calldata data)
        internal view returns (bytes32)
    {
        return _hash(
            abi.encodePacked(
                "BQV_EXECUTE_V1",
                block.chainid,
                address(this),
                laneNonce,
                idx,
                target,
                value,
                keccak256(data)
            )
        );
    }

    /// @dev `cachedRoot` key: (epoch << 64) | bottomTreeIdx.
    function _cacheKey(uint64 treeIdx) internal view returns (uint256) {
        return (uint256(epoch) << 64) | treeIdx;
    }

    /// @dev `_lane` key: (epoch << 8) | lane of `idx`.
    function _laneKey(uint64 idx) internal view returns (uint256) {
        return (uint256(epoch) << 8) | (idx >> LANE_SHIFT);
    }

    /// @dev Recompute the root of tree (`layer`, `treeIdx`) from a WOTS+
    ///      signature on `m` at `leafIdx` and the auth path.
    function _layerRoot(
        uint8 layer,
        uint64 treeIdx,
        uint32 leafIdx,
        bytes32 m,
        LayerSig calldata s
    ) internal view returns (bytes32 r) {
        uint256 seed = uint256(uint128(pkSeed));
        r = _wotsLeaf(seed, layer, treeIdx, leafIdx, m, s.wots);
        uint32 pos = leafIdx;
        for (uint256 k = 0; k < H; ++k) {
            r = _node(_adrs(seed, layer, treeIdx, 0x02, uint32(pos >> 1), uint8(k), 0), r, s.auth[k], pos & 1);
            pos >>= 1;
        }
    }

    /// @dev 64 base-16 message digits followed by 3 base-16 checksum digits.
    function _digits(bytes32 m) internal pure returns (uint8[67] memory d) {
        uint256 csum = 0;
        for (uint256 i = 0; i < 32; ++i) {
            uint8 b = uint8(m[i]);
            uint8 hi = b >> 4;
            uint8 lo = b & 0x0f;
            d[2 * i]     = hi;
            d[2 * i + 1] = lo;
            csum += (W - 1 - hi) + (W - 1 - lo);
        }
        // csum ≤ 64 * 15 = 960 < 16^3; encode as 3 big-endian base-16 digits.
        d[64] = uint8((csum >> 8) & 0x0f);
        d[65] = uint8((csum >> 4) & 0x0f);
        d[66] = uint8(csum & 0x0f);
    }

    /// @dev ADRS = layer(1) ‖ treeIdx(8) ‖ type(1) ‖ leafIdx(4) ‖ chainIdx(1) ‖ step(1) ‖ pkSeed(16).
    ///      `seed` is the public seed in the low 128 bits of a word.
    function _adrs(
        uint256 seed,
        uint8 layer,
        uint64 treeIdx,
        uint8 typ,
        uint32 leafIdx,
        uint8 chainIdx,
        uint8 step
    ) internal pure returns (bytes32) {
        return bytes32(
            (uint256(layer)    << 248) |
            (uint256(treeIdx)  << 184) |
            (uint256(typ)      << 176) |
            (uint256(leafIdx)  << 144) |
            (uint256(chainIdx) << 136) |
            (uint256(step)     << 128) |
            seed
        );
    }

    // ============================================================== views

    /// @notice Lane of a leaf index: its top LANE_BITS bits.
    function laneOf(uint64 idx) public pure returns (uint8) {
        return uint8(idx >> LANE_SHIFT);
    }

    /// @notice Next unused leaf index of `lane` in the current epoch (absolute
    ///         index; the first leaf of the lane when nothing has landed).
    function nextIdx(uint8 lane) public view returns (uint64) {
        uint64 n = uint64(_lane[(uint256(epoch) << 8) | lane]);
        uint64 first = uint64(uint256(lane) << LANE_SHIFT);
        return n > first ? n : first;
    }

    /// @notice Nonce of `lane` in the current epoch, bound into every digest of the lane.
    function nonce(uint8 lane) public view returns (uint64) {
        return uint64(_lane[(uint256(epoch) << 8) | lane] >> 64);
    }

    /// @notice Digest the client must sign for an `execute` at leaf `idx`
    ///         (`idx >= nextIdx(laneOf(idx))`) with the lane's current nonce.
    function digestAt(uint64 idx, address target, uint256 value, bytes calldata data)
        external view returns (bytes32)
    {
        return _digest(uint64(_lane[_laneKey(idx)] >> 64), idx, target, value, data);
    }

    /// @notice Whether an `execute` at leaf `idx` must include the top-layer proof.
    function needsTopLayerAt(uint64 idx) public view returns (bool) {
        return cachedRoot[_cacheKey(idx >> H)] == bytes32(0);
    }
}
