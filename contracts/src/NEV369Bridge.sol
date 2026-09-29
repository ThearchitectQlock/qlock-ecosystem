// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// OpenZeppelin v5 paths. v2 used security/Pausable.sol and
// security/ReentrancyGuard.sol, which are the v4 locations; wNEV-v2
// used the v5 path for Pausable. The two files could not compile
// against the same OZ version.
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {wNEV} from "./wNEV.sol";

/**
 * @title NEV369Bridge
 * @notice Trusted bridge between NEV369 (custom L1) and Ethereum.
 *
 * @dev ─── THE TRUST MODEL HAS NOT CHANGED ──────────────────────────
 *
 *      `mintFromNEV369` still mints on the relayer's word. There is no
 *      proof that a corresponding lock happened on NEV369 — no Merkle
 *      proof against a NEV369 block header, no light-client
 *      verification, no multi-signer threshold. A compromised relayer
 *      key mints wNEV out of nothing, up to whatever limit this
 *      contract enforces.
 *
 *      Everything below is damage limitation around that fact. None of
 *      it makes the bridge trustless. The real fix is either a light
 *      client that verifies NEV369 headers on Ethereum, or migrating to
 *      an audited cross-chain protocol. Both are large pieces of work
 *      and neither is in this file.
 *
 *      Worth stating in the same breath: NEV369 currently has an open
 *      critical consensus bug (NEV-001 — `validate_block_contents()`
 *      does not re-check balance or nonce, so an in-block double-spend
 *      mints from nothing). A bridge whose source chain can mint from
 *      nothing inherits that, and a cap on this side is not a defence
 *      against unbacked supply arriving through the front door. This
 *      bridge must not carry value until NEV-001 is fixed, whatever
 *      the contracts do.
 *
 *      ─── CHANGES FROM v2 ────────────────────────────────────────────
 *
 *      1. BURN ID is a monotonic nonce, not a hash of mutable context.
 *         v2 computed:
 *
 *           keccak256(msg.sender, amount, nev369Address,
 *                     block.timestamp, block.number)
 *
 *         Two identical burns by the same user in the same block
 *         produce the same id, so the second reverts with "burn id
 *         collision" — a legitimate user action failing for no reason
 *         the user can see or fix. It fails closed, so no funds are at
 *         risk, but it is a liveness bug in the normal path. Separately,
 *         `abi.encodePacked` over a dynamic `string` sitting between
 *         other fields is ambiguous encoding, which is the same class
 *         of bug as NEV369's old delimiter-free `format!` signing
 *         bytes. A counter has neither problem.
 *
 *      2. PER-WINDOW MINT LIMIT. The only cap in v2 was MAX_SUPPLY,
 *         set about 5.4x above the amount of NEV that can ever exist
 *         (see wNEV.MAX_SUPPLY). It never binds, so it never limits a
 *         compromised relayer. `mintLimitPerWindow` is operator-set,
 *         can only be lowered without a timelock, and needs the 48-hour
 *         delay to raise. That is the difference between "a stolen
 *         relayer key drains everything in one transaction" and "it
 *         drains one window's worth and someone has time to pause".
 *
 *      3. `totalMinted` is no longer decremented on burn. In v2 a
 *         mint/burn cycle freed cap headroom, so cumulative minting was
 *         unbounded even though instantaneous supply was capped. That is
 *         arguably correct for a supply cap, but it makes `totalMinted`
 *         useless as an audit figure. Two counters now: `totalMinted`
 *         (monotonic, for reconciliation against NEV369's locked
 *         balance) and wNEV's own `totalSupply()` (circulating).
 *
 *      4. Burn requires an allowance, matching wNEV's allowance-based
 *         `burn`. The contract pulls it from `msg.sender` only.
 *
 * STILL REQUIRES A PROFESSIONAL AUDIT BEFORE ANY MAINNET DEPLOYMENT.
 */
contract NEV369Bridge is AccessControl, Pausable, ReentrancyGuard, EIP712 {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    // ─────────────────────────────────────────────────────────────────

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // ─────────────────────────────────────────────────────────────────
    // ON-CHAIN THRESHOLD  —  replaces RELAYER_ROLE
    //
    // RELAYER_ROLE used to gate minting, so any single address holding
    // it could mint. godshield-bridge collects m-of-n Dilithium5
    // attestations off-chain, but THIS CONTRACT COULD NOT SEE THEM:
    // Ethereum has no ML-DSA precompile, so verifying a Dilithium
    // signature on-chain is not possible today at any gas price.
    //
    // A threshold enforced only off-chain is not enforced. The
    // contract would still mint for whoever held the role, whatever the
    // coordinator decided.
    //
    // So this is hybrid, which is what GodShield's own whitepaper
    // describes for exactly this situation: each signer ALSO holds a
    // secp256k1 key and signs the same authorization, and the contract
    // verifies m-of-n ECDSA. The Dilithium5 attestations remain the
    // post-quantum audit trail — a 2026 ECDSA signature is forgeable by
    // a future CRQC, a 2026 Dilithium5 attestation over the same record
    // is not.
    //
    // Stated plainly rather than buried: the ON-CHAIN enforcement here
    // is classical. It is post-quantum ATTESTED, not post-quantum
    // enforced, and it will remain so until Ethereum ships a
    // lattice-signature precompile.
    // ─────────────────────────────────────────────────────────────────

    /// secp256k1 addresses permitted to authorize a mint.
    mapping(address => bool) public isSigner;
    uint256 public signerCount;

    /// How many distinct signers must sign. Never 1 — see setThreshold.
    uint256 public signerThreshold;

    /// EIP-712 typehash for a mint authorization. Changing this
    /// invalidates every signature already collected for an in-flight
    /// mint, so bump the name/version in the constructor instead.
    bytes32 private constant MINT_AUTHORIZATION_TYPEHASH = keccak256(
        "MintAuthorization(bytes32 lockId,address recipient,uint256 amount,"
        "uint256 sourceBlockHeight,string sourceTx)"
    );

    wNEV public immutable wnev;

    /// @dev 8 decimals, matching wNEV and NEV369 base units.
    ///      1e5 base units = 0.001 NEV. v2's 1e15 was 0.001 at 18
    ///      decimals; at 8 decimals it would be 10,000,000 NEV, which
    ///      would have rejected essentially every real transfer.
    uint256 public constant MIN_LOCK_AMOUNT = 1e5;

    /// @notice Mirrors wNEV.MAX_SUPPLY and chain.rs MAX_SUPPLY.
    ///         Defense in depth so a bug in one contract does not depend
    ///         on the other's check. Does not bind — see wNEV.
    uint256 public constant MAX_SUPPLY = 369_369_369 * 1e8;

    uint256 public constant TIMELOCK_DELAY = 48 hours;
    uint256 public constant MINT_WINDOW = 24 hours;

    /// @notice Monotonic. Total ever minted by this bridge, never
    ///         decremented. Reconcile against the balance locked on
    ///         NEV369: a divergence is the signal that the relayer is
    ///         minting unbacked supply.
    uint256 public totalMinted;

    /// @notice Per-window mint ceiling. Zero means minting is disabled,
    ///         which is the deploy-time default on purpose — the
    ///         operator must make a deliberate decision about how much
    ///         a stolen relayer key is allowed to be worth.
    uint256 public mintLimitPerWindow;
    uint256 public mintedInWindow;
    uint256 public windowStart;

    uint256 public pendingMintLimit;
    uint256 public pendingMintLimitEta;

    uint256 public burnNonce;

    mapping(bytes32 => bool) public processedLocks;
    mapping(bytes32 => bool) public processedBurns;

    // ─────────────────────────────────────────────────────────────────

    event WrappedMinted(
        address indexed user, uint256 amount, bytes32 indexed nev369LockId, string sourceTx
    );
    event WrappedBurned(
        address indexed user, uint256 amount, string nev369Address, bytes32 indexed burnId
    );
    event MintLimitProposed(uint256 newLimit, uint256 eta);
    event MintLimitChanged(uint256 oldLimit, uint256 newLimit);
    event MintWindowRolled(uint256 newWindowStart);
    event RescueExecuted(address indexed token, address indexed to, uint256 amount);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ThresholdChanged(uint256 oldThreshold, uint256 newThreshold);

    // ─────────────────────────────────────────────────────────────────

    error ZeroAddress();
    error AmountTooSmall(uint256 given, uint256 minimum);
    error AlreadyProcessed(bytes32 id);
    error ExceedsMaxSupply(uint256 requested, uint256 remaining);
    error MintingDisabled();
    error ExceedsWindowLimit(uint256 requested, uint256 remainingInWindow);
    error EmptyDestination();
    error NoPendingLimit();
    error TimelockNotElapsed(uint256 eta, uint256 now_);
    error CannotRescueWnev();
    error ThresholdNotMet(uint256 got, uint256 need);
    error NotASigner(address recovered);
    error SignaturesOutOfOrder();
    error ThresholdTooLow();
    error ThresholdExceedsSigners(uint256 threshold, uint256 signers);

    /**
     * @param _wnev    Deployed wNEV.
     * @param admin    MUST be a multisig beyond local testing.
     * @param signers_ secp256k1 addresses of the independent signers.
     * @param threshold_ How many must sign. Must be >= 2.
     *
     * @dev `mintLimitPerWindow` starts at 0, so the bridge cannot mint
     *      until the admin sets it. Deploying into a state where minting
     *      already works at the full cap would make the limit decorative.
     */
    constructor(address _wnev, address admin, address[] memory signers_, uint256 threshold_)
        EIP712("NEV369Bridge", "1")
    {
        if (_wnev == address(0) || admin == address(0)) revert ZeroAddress();

        wnev = wNEV(_wnev);

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);

        for (uint256 i = 0; i < signers_.length; i++) {
            address sgn = signers_[i];
            if (sgn == address(0)) revert ZeroAddress();
            if (!isSigner[sgn]) {
                isSigner[sgn] = true;
                signerCount++;
                emit SignerAdded(sgn);
            }
        }

        // Refused in the constructor, not merely documented. A threshold
        // of one is the single-relayer model under another name, and a
        // deploy script should not be able to configure it by accident.
        if (threshold_ < 2) revert ThresholdTooLow();
        if (threshold_ > signerCount) {
            revert ThresholdExceedsSigners(threshold_, signerCount);
        }
        signerThreshold = threshold_;

        windowStart = block.timestamp;
    }

    // ─────────────────────────────────────────────────────────────────
    // Signer set management
    // ─────────────────────────────────────────────────────────────────

    function addSigner(address sgn) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (sgn == address(0)) revert ZeroAddress();
        if (isSigner[sgn]) return;
        isSigner[sgn] = true;
        signerCount++;
        emit SignerAdded(sgn);
    }

    /// @dev Cannot drop the signer count below the threshold — doing so
    ///      would brick minting until someone noticed, and "bridge is
    ///      stuck" is a worse failure to diagnose than a refused removal.
    function removeSigner(address sgn) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!isSigner[sgn]) return;
        if (signerCount - 1 < signerThreshold) {
            revert ThresholdExceedsSigners(signerThreshold, signerCount - 1);
        }
        isSigner[sgn] = false;
        signerCount--;
        emit SignerRemoved(sgn);
    }

    function setThreshold(uint256 newThreshold) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newThreshold < 2) revert ThresholdTooLow();
        if (newThreshold > signerCount) {
            revert ThresholdExceedsSigners(newThreshold, signerCount);
        }
        emit ThresholdChanged(signerThreshold, newThreshold);
        signerThreshold = newThreshold;
    }

    /// @notice The EIP-712 digest signers must sign.
    ///
    /// @dev Exposed so a signer can compute exactly what the contract
    ///      will check, rather than trusting a relayer to hand them the
    ///      right bytes. EIP-712 binds the chain id and this contract
    ///      address, so a signature gathered for a testnet deployment
    ///      cannot be replayed against mainnet.
    function mintDigest(
        bytes32 lockId,
        address recipient,
        uint256 amount,
        uint256 sourceBlockHeight,
        string calldata sourceTx
    ) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    MINT_AUTHORIZATION_TYPEHASH,
                    lockId,
                    recipient,
                    amount,
                    sourceBlockHeight,
                    keccak256(bytes(sourceTx))
                )
            )
        );
    }

    // ─────────────────────────────────────────────────────────────────
    // Pause — immediate
    // ─────────────────────────────────────────────────────────────────

    /**
     * @dev NOTE FOR THE INCIDENT RUNBOOK: there are TWO pause switches,
     *      one here and one on wNEV, with separately granted PAUSER_ROLE.
     *      Pausing this contract stops bridge entry and exit; pausing
     *      wNEV stops all mint and burn including from any other bridge
     *      version that still holds BRIDGE_ROLE.
     *
     *      During an incident, hit both. Pausing only the bridge leaves
     *      an overlapping older bridge able to mint.
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // ─────────────────────────────────────────────────────────────────
    // Mint limit — lowering is immediate, raising is delayed
    // ─────────────────────────────────────────────────────────────────

    /// @notice Lower the per-window limit. No delay: tightening is
    ///         always safe and may be urgent.
    function lowerMintLimit(uint256 newLimit) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 old = mintLimitPerWindow;
        require(newLimit < old, "Bridge: use proposeMintLimit to raise");
        mintLimitPerWindow = newLimit;
        emit MintLimitChanged(old, newLimit);
    }

    /// @notice Raising the limit is timelocked. A compromised admin key
    ///         cannot raise the ceiling and drain in the same block.
    function proposeMintLimit(uint256 newLimit) external onlyRole(DEFAULT_ADMIN_ROLE) {
        pendingMintLimit = newLimit;
        pendingMintLimitEta = block.timestamp + TIMELOCK_DELAY;
        emit MintLimitProposed(newLimit, pendingMintLimitEta);
    }

    function finalizeMintLimit() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (pendingMintLimitEta == 0) revert NoPendingLimit();
        if (block.timestamp < pendingMintLimitEta) {
            revert TimelockNotElapsed(pendingMintLimitEta, block.timestamp);
        }
        uint256 old = mintLimitPerWindow;
        mintLimitPerWindow = pendingMintLimit;
        pendingMintLimit = 0;
        pendingMintLimitEta = 0;
        emit MintLimitChanged(old, mintLimitPerWindow);
    }

    // ─────────────────────────────────────────────────────────────────
    // NEV369 → Ethereum
    // ─────────────────────────────────────────────────────────────────

    /**
     * @notice Mint wNEV against an asserted lock on NEV369.
     *
     * @param amount `amount` is in NEV369 BASE UNITS (8 decimals), and
     *        wNEV uses the same 8 decimals, so this is a 1:1 pass
     *        through with no scaling. Do not scale in the relayer.
     *
     * @dev The relayer's assertion is the only evidence a lock occurred.
     *      Everything here is a bound on how wrong that can go.
     */
    /**
     * @notice Mint wNEV against a threshold-authorized NEV369 lock.
     *
     * @param signatures m-of-n secp256k1 signatures over `mintDigest`,
     *        ORDERED BY ASCENDING SIGNER ADDRESS.
     *
     * @dev This was gated by a single role. Any one holder of it could
     *      mint. Now the caller is irrelevant — anyone may submit, and
     *      the signatures are what authorize. That is deliberate: a
     *      compromised submitter can withhold or reorder mints but
     *      cannot create one, which is the same property
     *      godshield-bridge gives the off-chain coordinator.
     *
     *      ASCENDING ORDER is how distinctness is enforced. Recovering m
     *      signatures and counting them lets one compromised key sign m
     *      times and clear the bar alone — the classic threshold bug, and
     *      exactly what godshield-bridge rejects off-chain. Requiring
     *      strictly increasing addresses makes a duplicate impossible to
     *      express, and costs no storage.
     */
    function mintFromNEV369(
        address user,
        uint256 amount,
        bytes32 nev369LockId,
        string calldata sourceTx,
        uint256 sourceBlockHeight,
        bytes[] calldata signatures
    ) external whenNotPaused nonReentrant {
        if (user == address(0)) revert ZeroAddress();
        if (amount < MIN_LOCK_AMOUNT) revert AmountTooSmall(amount, MIN_LOCK_AMOUNT);
        if (processedLocks[nev369LockId]) revert AlreadyProcessed(nev369LockId);

        // ── Threshold, before any state is touched ──
        if (signatures.length < signerThreshold) {
            revert ThresholdNotMet(signatures.length, signerThreshold);
        }

        bytes32 digest = mintDigest(nev369LockId, user, amount, sourceBlockHeight, sourceTx);

        address last = address(0);
        for (uint256 i = 0; i < signatures.length; i++) {
            address recovered = digest.recover(signatures[i]);
            if (!isSigner[recovered]) revert NotASigner(recovered);
            // Strictly increasing: rejects a repeat and a wrong order in
            // a single comparison.
            if (recovered <= last) revert SignaturesOutOfOrder();
            last = recovered;
        }

        // Roll the window lazily. No keeper, no cron — the first mint
        // after a window elapses resets the counter.
        if (block.timestamp >= windowStart + MINT_WINDOW) {
            windowStart = block.timestamp;
            mintedInWindow = 0;
            emit MintWindowRolled(windowStart);
        }

        uint256 limit = mintLimitPerWindow;
        if (limit == 0) revert MintingDisabled();
        if (mintedInWindow + amount > limit) {
            revert ExceedsWindowLimit(amount, limit - mintedInWindow);
        }

        if (totalMinted + amount > MAX_SUPPLY) {
            revert ExceedsMaxSupply(amount, MAX_SUPPLY - totalMinted);
        }

        processedLocks[nev369LockId] = true;
        mintedInWindow += amount;
        totalMinted += amount;

        wnev.mint(user, amount);

        emit WrappedMinted(user, amount, nev369LockId, sourceTx);
    }

    // ─────────────────────────────────────────────────────────────────
    // Ethereum → NEV369
    // ─────────────────────────────────────────────────────────────────

    /**
     * @notice Burn wNEV and signal a release on NEV369.
     *
     * @dev Requires an ERC-20 approval to this contract first, because
     *      wNEV's `burn` is allowance-based now. That is one extra
     *      transaction for the user and one fewer capability for
     *      BRIDGE_ROLE to hold.
     *
     *      `burnId` is `keccak256(address(this), chainid, nonce)`. The
     *      nonce makes it collision-free by construction, the chain id
     *      stops an id produced on a testnet deployment from colliding
     *      with mainnet, and `address(this)` separates bridge versions.
     *      No mutable block context, so two identical burns in one
     *      block both succeed — which v2 rejected.
     */
    function burnToNEV369(uint256 amount, string calldata nev369Address)
        external
        whenNotPaused
        nonReentrant
        returns (bytes32 burnId)
    {
        if (amount < MIN_LOCK_AMOUNT) revert AmountTooSmall(amount, MIN_LOCK_AMOUNT);
        if (bytes(nev369Address).length == 0) revert EmptyDestination();

        unchecked {
            ++burnNonce;
        }
        burnId = keccak256(abi.encode(address(this), block.chainid, burnNonce));

        // Cannot collide given a monotonic nonce. Kept as an assertion
        // rather than removed: if it ever fires, the nonce logic is
        // broken and failing closed is the right answer.
        if (processedBurns[burnId]) revert AlreadyProcessed(burnId);
        processedBurns[burnId] = true;

        // totalMinted is NOT decremented. See note 3 in the contract
        // docs — it is a monotonic audit figure, not a live balance.
        // Circulating supply is wnev.totalSupply().

        wnev.burn(msg.sender, amount);

        emit WrappedBurned(msg.sender, amount, nev369Address, burnId);
    }

    // ─────────────────────────────────────────────────────────────────
    // Views
    // ─────────────────────────────────────────────────────────────────

    /// @notice What the relayer can still mint in the current window.
    ///         Monitor this: a sustained pin at zero means either the
    ///         limit is set too low for real volume, or something is
    ///         minting far more than it should.
    function remainingInWindow() external view returns (uint256) {
        if (block.timestamp >= windowStart + MINT_WINDOW) return mintLimitPerWindow;
        uint256 used = mintedInWindow;
        return used >= mintLimitPerWindow ? 0 : mintLimitPerWindow - used;
    }

    /// @notice Circulating wNEV. Compare against the balance locked on
    ///         NEV369 — they must match, and a gap is unbacked supply.
    function circulatingSupply() external view returns (uint256) {
        return wnev.totalSupply();
    }

    // ─────────────────────────────────────────────────────────────────
    // Rescue
    // ─────────────────────────────────────────────────────────────────

    /**
     * @dev wNEV is explicitly excluded, carried over from v2. The
     *      consequence, stated rather than buried: wNEV sent here by
     *      mistake is permanently stuck. That is the deliberate trade —
     *      an admin able to move wNEV out of the bridge is an admin able
     *      to take user funds, which is worse than a stuck transfer.
     *
     *      No ETH rescue either: this contract has no `receive` or
     *      `payable` function, so plain ETH transfers to it revert.
     *      Nothing to rescue.
     */
    function rescueERC20(address token, address to, uint256 amount)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (to == address(0)) revert ZeroAddress();
        if (token == address(wnev)) revert CannotRescueWnev();
        IERC20(token).safeTransfer(to, amount);
        emit RescueExecuted(token, to, amount);
    }
}
