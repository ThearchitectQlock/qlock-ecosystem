// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// OpenZeppelin v5 paths throughout. Pausable and ReentrancyGuard live
// under utils/ in v5, not security/. NEV369Bridge.sol now uses the same
// paths — as supplied the two files disagreed and could not compile
// against any single OZ version.
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title wNEV — Wrapped NEV369
 * @notice ERC-20 representation of NEV369 on Ethereum.
 *
 * @dev CHANGES FROM v2, and why each one matters:
 *
 *  1. DECIMALS: 18 → 8.  This is the fund-loss fix.
 *
 *     NEV369 uses 8 decimals (chain.rs: `DECIMALS: u32 = 8`,
 *     `UNITS_PER_NEV: Amount = 100_000_000`). wNEV used the ERC-20
 *     default of 18 and nothing anywhere scaled between them.
 *
 *     A relayer passing a NEV369 base-unit amount straight into
 *     `mintFromNEV369` would have minted 10^10 times too little: lock
 *     1 NEV (100_000_000 base units) on the chain, receive
 *     0.0000000001 wNEV. Scaling in the relayer instead just moves a
 *     silent 10-decimal multiplication across a trust boundary where
 *     getting it backwards mints 10^10 times too much.
 *
 *     Matching decimals removes the conversion entirely. One NEV369
 *     base unit is one wNEV base unit, exactly, forever. Six-decimal
 *     tokens (USDC) are routine; a unit mismatch on a bridge is not.
 *
 *  2. SUPPLY CAP: mirrors chain.rs `MAX_SUPPLY` exactly, and says
 *     plainly that it does not bind. See the note on MAX_SUPPLY below.
 *
 *  3. `burn` is now allowance-based. v2's `burn(from, amount)` called
 *     `_burn` directly with no allowance check, which made it an
 *     unrestricted "destroy any holder's balance" primitive granted to
 *     BRIDGE_ROLE. The bridge only ever burned `msg.sender`, so the
 *     deployed path was safe — but the capability existed, and a future
 *     bridge version or a compromised BRIDGE_ROLE could zero any
 *     account. `_spendAllowance` makes the grant explicit.
 *
 *  4. `BridgeRoleFinalized` emitted `msg.sender` (the admin) in the
 *     slot documented as `oldBridge`. Any off-chain indexer tracking
 *     bridge rotation recorded the admin as the previous bridge.
 *     `currentBridge` is now tracked so the event is truthful.
 *
 *  5. AccessControlEnumerable is deliberately NOT used — see the note
 *     on role accumulation in `finalizeBridge`.
 *
 * STILL REQUIRES A PROFESSIONAL AUDIT BEFORE ANY MAINNET DEPLOYMENT.
 * Code-level hardening is not independent review, and none of the
 * reasoning in these comments has been checked by anyone but its author.
 */
contract wNEV is ERC20, AccessControl, Pausable {
    // ─────────────────────────────────────────────────────────────────
    // Roles
    // ─────────────────────────────────────────────────────────────────

    bytes32 public constant BRIDGE_ROLE = keccak256("BRIDGE_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // ─────────────────────────────────────────────────────────────────
    // Decimals
    // ─────────────────────────────────────────────────────────────────

    /// @dev 8, matching NEV369's base units exactly. See note 1 above.
    ///      Changing this is a fund-loss change, not a cosmetic one.
    uint8 private constant DECIMALS = 8;

    function decimals() public pure override returns (uint8) {
        return DECIMALS;
    }

    // ─────────────────────────────────────────────────────────────────
    // Supply cap
    // ─────────────────────────────────────────────────────────────────

    /// @notice Mirrors NEV369's `MAX_SUPPLY` constant exactly:
    ///         369,369,369 NEV at 8 decimals = 36_936_936_900_000_000.
    ///
    /// @dev READ THIS BEFORE RELYING ON IT AS A SAFETY PROPERTY.
    ///
    ///      This cap does not bind, and v2's comment claiming wNEV
    ///      "should never be able to exceed what could exist natively on
    ///      NEV369" was wrong by a factor of about 5.4.
    ///
    ///      NEV369's emission schedule is 50 NEV halving every 210,000
    ///      blocks, which totals 210_000 * 50 * 2 = 21,000,000 NEV
    ///      across every epoch combined. Plus the 46,900,000 premine,
    ///      the most NEV that can ever exist is roughly 67,900,000 —
    ///      about 18% of this number. `MAX_SUPPLY` on both sides is an
    ///      unreachable ceiling, which is why the equivalent check in
    ///      chain.rs `validate_block_contents()` never fires either.
    ///
    ///      A cap set five times above anything that can exist is not a
    ///      control. The real mitigation for a trusted relayer is the
    ///      per-window mint limit in NEV369Bridge, which is enforced
    ///      against an operator-set number that actually binds.
    ///
    ///      Kept, and kept identical to the chain constant, so the two
    ///      sides cannot silently diverge — not because it protects
    ///      anything on its own.
    uint256 public constant MAX_SUPPLY = 369_369_369 * 10 ** uint256(DECIMALS);

    // ─────────────────────────────────────────────────────────────────
    // Timelocked bridge rotation
    // ─────────────────────────────────────────────────────────────────

    uint256 public constant TIMELOCK_DELAY = 48 hours;

    address public pendingBridge;
    uint256 public pendingBridgeEta;

    /// @notice The most recently finalized bridge. Tracked so
    ///         `BridgeRoleFinalized` can report a truthful `oldBridge`.
    address public currentBridge;

    event BridgeRoleProposed(address indexed proposed, uint256 eta);
    event BridgeRoleFinalized(address indexed oldBridge, address indexed newBridge);
    event BridgeRoleCancelled(address indexed cancelled);

    // ─────────────────────────────────────────────────────────────────

    error ZeroAddress();
    error NoPendingBridge();
    error TimelockNotElapsed(uint256 eta, uint256 now_);
    error ExceedsMaxSupply(uint256 requested, uint256 remaining);

    /**
     * @param admin Role admin. MUST be a multisig (Gnosis Safe or
     *        equivalent) for anything beyond local testing. A single EOA
     *        here means one compromised key can propose a bridge, wait
     *        48 hours, and mint to the cap.
     */
    constructor(address admin) ERC20("Wrapped NEV369", "wNEV") {
        if (admin == address(0)) revert ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
    }

    // ─────────────────────────────────────────────────────────────────
    // Bridge rotation — proposed, delayed, finalized
    // ─────────────────────────────────────────────────────────────────

    function proposeBridge(address newBridge) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newBridge == address(0)) revert ZeroAddress();
        pendingBridge = newBridge;
        pendingBridgeEta = block.timestamp + TIMELOCK_DELAY;
        emit BridgeRoleProposed(newBridge, pendingBridgeEta);
    }

    function cancelPendingBridge() external onlyRole(DEFAULT_ADMIN_ROLE) {
        address cancelled = pendingBridge;
        pendingBridge = address(0);
        pendingBridgeEta = 0;
        emit BridgeRoleCancelled(cancelled);
    }

    /**
     * @notice Grant BRIDGE_ROLE to the pending address once the delay has
     *         elapsed.
     *
     * @dev The old bridge's role is NOT revoked here. That is deliberate
     *      and carried over from v2, so two bridge versions can overlap
     *      during a migration.
     *
     *      The cost of that choice: BRIDGE_ROLE holders accumulate, and
     *      plain AccessControl cannot enumerate them, so there is no
     *      on-chain way to answer "which addresses can mint wNEV right
     *      now". Over several rotations that becomes genuinely unknown.
     *
     *      Using AccessControlEnumerable would fix the enumeration but
     *      also make the full mint-authority set trivially readable by
     *      anyone picking targets. The operational answer is to revoke
     *      explicitly: every `finalizeBridge` should be followed by
     *      `revokeRole(BRIDGE_ROLE, oldBridge)` once the migration
     *      window closes. That belongs in the incident runbook, and it
     *      is a process control, which is weaker than a code control.
     *      Flagged rather than hidden.
     */
    function finalizeBridge() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (pendingBridge == address(0)) revert NoPendingBridge();
        if (block.timestamp < pendingBridgeEta) {
            revert TimelockNotElapsed(pendingBridgeEta, block.timestamp);
        }

        address oldBridge = currentBridge;
        address newBridge = pendingBridge;

        _grantRole(BRIDGE_ROLE, newBridge);
        currentBridge = newBridge;

        pendingBridge = address(0);
        pendingBridgeEta = 0;

        emit BridgeRoleFinalized(oldBridge, newBridge);
    }

    // ─────────────────────────────────────────────────────────────────
    // Pause — immediate, no timelock. Delaying an emergency brake
    // defeats its purpose.
    // ─────────────────────────────────────────────────────────────────

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // ─────────────────────────────────────────────────────────────────
    // Mint / burn
    // ─────────────────────────────────────────────────────────────────

    function mint(address to, uint256 amount) external onlyRole(BRIDGE_ROLE) whenNotPaused {
        uint256 supply = totalSupply();
        if (supply + amount > MAX_SUPPLY) {
            revert ExceedsMaxSupply(amount, MAX_SUPPLY - supply);
        }
        _mint(to, amount);
    }

    /**
     * @notice Burn `amount` from `from`, consuming the bridge's allowance.
     *
     * @dev Allowance-based, unlike v2. The bridge must hold an ERC-20
     *      approval from the holder, which means a user's tokens cannot
     *      be destroyed without an on-chain act of consent from that
     *      user. This changes the integration: `burnToNEV369` now
     *      requires an `approve` first, and the bridge's own burn path
     *      handles that.
     */
    function burn(address from, uint256 amount) external onlyRole(BRIDGE_ROLE) whenNotPaused {
        _spendAllowance(from, _msgSender(), amount);
        _burn(from, amount);
    }
}
