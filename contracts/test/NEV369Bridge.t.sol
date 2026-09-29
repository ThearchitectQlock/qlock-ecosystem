// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {wNEV} from "../src/wNEV.sol";
import {NEV369Bridge} from "../src/NEV369Bridge.sol";

/**
 * REWRITTEN for the threshold API.
 *
 * The previous suite did not compile. It still called the three-argument
 * constructor `new NEV369Bridge(wnev, admin, relayer)` and the
 * four-argument `mintFromNEV369(...)` with no signatures array — the
 * single-role shape that was removed when minting moved to m-of-n.
 *
 * A test suite that does not build is worse than none: CI goes red for a
 * reason nobody reads, and the regressions it was guarding quietly stop
 * being checked.
 *
 * Each test below pins either a defect found in the v2 contracts or a
 * property of the threshold scheme.
 */
contract NEV369BridgeTest is Test {
    wNEV internal token;
    NEV369Bridge internal bridge;

    address internal admin = address(0xA11CE);
    address internal user = address(0xCAFE);

    // Foundry derives the address from the key, so these are the
    // identities the contract will recover from a signature.
    uint256 internal pk1 = 0xA1;
    uint256 internal pk2 = 0xA2;
    uint256 internal pk3 = 0xA3;
    uint256 internal pkOutsider = 0xBAD;

    address internal s1;
    address internal s2;
    address internal s3;

    uint256 internal constant ONE_NEV = 1e8; // 8 decimals
    uint256 internal constant WINDOW_LIMIT = 1_000_000 * ONE_NEV;

    function setUp() public {
        s1 = vm.addr(pk1);
        s2 = vm.addr(pk2);
        s3 = vm.addr(pk3);

        address[] memory signers = new address[](3);
        signers[0] = s1;
        signers[1] = s2;
        signers[2] = s3;

        token = new wNEV(admin);
        bridge = new NEV369Bridge(address(token), admin, signers, 2);

        vm.startPrank(admin);
        token.proposeBridge(address(bridge));
        vm.warp(block.timestamp + 48 hours);
        token.finalizeBridge();

        bridge.proposeMintLimit(WINDOW_LIMIT);
        vm.warp(block.timestamp + 48 hours);
        bridge.finalizeMintLimit();
        vm.stopPrank();
    }

    // ── helpers ──────────────────────────────────────────────────────

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// Signatures must arrive ordered by ascending signer address — that
    /// is how the contract enforces distinctness — so sort the keys by
    /// the address they derive to.
    function _sorted(uint256 a, uint256 b) internal pure returns (uint256, uint256) {
        return vm.addr(a) < vm.addr(b) ? (a, b) : (b, a);
    }

    function _sigs(
        bytes32 lockId,
        address to,
        uint256 amount,
        uint256 height,
        string memory srcTx,
        uint256 keyA,
        uint256 keyB
    ) internal view returns (bytes[] memory out) {
        bytes32 digest = bridge.mintDigest(lockId, to, amount, height, srcTx);
        (uint256 lo, uint256 hi) = _sorted(keyA, keyB);
        out = new bytes[](2);
        out[0] = _sign(lo, digest);
        out[1] = _sign(hi, digest);
    }

    // ── The model this replaces ──────────────────────────────────────

    function test_threshold_of_one_is_refused() public {
        address[] memory one = new address[](1);
        one[0] = s1;
        wNEV t = new wNEV(admin);
        vm.expectRevert(NEV369Bridge.ThresholdTooLow.selector);
        new NEV369Bridge(address(t), admin, one, 1);
    }

    function test_threshold_above_signer_count_is_refused() public {
        address[] memory two = new address[](2);
        two[0] = s1;
        two[1] = s2;
        wNEV t = new wNEV(admin);
        vm.expectRevert(abi.encodeWithSelector(NEV369Bridge.ThresholdExceedsSigners.selector, 3, 2));
        new NEV369Bridge(address(t), admin, two, 3);
    }

    function test_one_key_cannot_reach_threshold_by_signing_twice() public {
        // The classic threshold bug: counting signatures, not signers.
        bytes32 lockId = keccak256("lock-dup");
        bytes32 digest = bridge.mintDigest(lockId, user, ONE_NEV, 100, "tx");
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(pk1, digest);
        sigs[1] = _sign(pk1, digest);

        vm.expectRevert(NEV369Bridge.SignaturesOutOfOrder.selector);
        bridge.mintFromNEV369(user, ONE_NEV, lockId, "tx", 100, sigs);
    }

    // ── Happy path ───────────────────────────────────────────────────

    function test_two_distinct_signers_authorize_a_mint() public {
        bytes32 lockId = keccak256("lock-1");
        bytes[] memory sigs = _sigs(lockId, user, ONE_NEV, 100, "tx", pk1, pk2);

        bridge.mintFromNEV369(user, ONE_NEV, lockId, "tx", 100, sigs);

        assertEq(token.balanceOf(user), ONE_NEV);
        assertEq(bridge.totalMinted(), ONE_NEV);
    }

    function test_the_caller_is_irrelevant() public {
        // A compromised submitter can withhold or reorder, not create.
        bytes32 lockId = keccak256("lock-anyone");
        bytes[] memory sigs = _sigs(lockId, user, ONE_NEV, 100, "tx", pk1, pk3);

        vm.prank(address(0xD15EA5E));
        bridge.mintFromNEV369(user, ONE_NEV, lockId, "tx", 100, sigs);
        assertEq(token.balanceOf(user), ONE_NEV);
    }

    // ── Signature binding ────────────────────────────────────────────

    function test_an_outside_key_is_rejected() public {
        bytes32 lockId = keccak256("lock-out");
        bytes32 digest = bridge.mintDigest(lockId, user, ONE_NEV, 100, "tx");
        (uint256 lo, uint256 hi) = _sorted(pk1, pkOutsider);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(lo, digest);
        sigs[1] = _sign(hi, digest);

        vm.expectRevert();
        bridge.mintFromNEV369(user, ONE_NEV, lockId, "tx", 100, sigs);
    }

    function test_signatures_do_not_transfer_to_a_different_amount() public {
        // Signers approved 1 NEV; the same signatures are submitted
        // against 1,000,000. Recovery yields addresses that are not
        // signers, so it reverts.
        bytes32 lockId = keccak256("lock-swap");
        bytes[] memory sigs = _sigs(lockId, user, ONE_NEV, 100, "tx", pk1, pk2);

        vm.expectRevert();
        bridge.mintFromNEV369(user, 1_000_000 * ONE_NEV, lockId, "tx", 100, sigs);
    }

    function test_signatures_do_not_transfer_to_a_different_recipient() public {
        bytes32 lockId = keccak256("lock-redirect");
        bytes[] memory sigs = _sigs(lockId, user, ONE_NEV, 100, "tx", pk1, pk2);

        vm.expectRevert();
        bridge.mintFromNEV369(address(0xBAD), ONE_NEV, lockId, "tx", 100, sigs);
    }

    function test_digest_is_eip712_not_a_bare_hash() public view {
        // EIP-712 binds chain id and verifying contract, so signatures
        // gathered against a testnet deployment cannot be replayed on
        // mainnet.
        bytes32 d1 = bridge.mintDigest(keccak256("x"), user, ONE_NEV, 100, "tx");
        bytes32 d2 = keccak256(abi.encode(keccak256("x"), user, ONE_NEV, 100, "tx"));
        assertTrue(d1 != d2);
    }

    // ── Replay ───────────────────────────────────────────────────────

    function test_the_same_lock_cannot_mint_twice() public {
        bytes32 lockId = keccak256("lock-replay");
        bytes[] memory sigs = _sigs(lockId, user, ONE_NEV, 100, "tx", pk1, pk2);

        bridge.mintFromNEV369(user, ONE_NEV, lockId, "tx", 100, sigs);
        vm.expectRevert(abi.encodeWithSelector(NEV369Bridge.AlreadyProcessed.selector, lockId));
        bridge.mintFromNEV369(user, ONE_NEV, lockId, "tx", 100, sigs);

        assertEq(bridge.totalMinted(), ONE_NEV, "a replay must not add supply");
    }

    // ── Decimals — the fund-loss defect ──────────────────────────────

    function test_decimals_match_nev369_base_units() public view {
        assertEq(token.decimals(), 8);
    }

    function test_one_nev_locked_mints_exactly_one_wnev() public {
        bytes32 lockId = keccak256("lock-unit");
        bytes[] memory sigs = _sigs(lockId, user, ONE_NEV, 100, "tx", pk1, pk2);
        bridge.mintFromNEV369(user, ONE_NEV, lockId, "tx", 100, sigs);
        // Under the old 18-decimal wNEV this produced 1e-10 wNEV.
        assertEq(token.balanceOf(user), ONE_NEV);
    }

    function test_supply_caps_agree() public view {
        assertEq(token.MAX_SUPPLY(), 36_936_936_900_000_000);
        assertEq(bridge.MAX_SUPPLY(), token.MAX_SUPPLY());
    }

    // ── Limits ───────────────────────────────────────────────────────

    function test_minting_is_disabled_until_a_limit_is_set() public {
        address[] memory signers = new address[](3);
        signers[0] = s1;
        signers[1] = s2;
        signers[2] = s3;
        wNEV t2 = new wNEV(admin);
        NEV369Bridge b2 = new NEV369Bridge(address(t2), admin, signers, 2);

        vm.startPrank(admin);
        t2.proposeBridge(address(b2));
        vm.warp(block.timestamp + 48 hours);
        t2.finalizeBridge();
        vm.stopPrank();

        bytes32 lockId = keccak256("lock-nolimit");
        bytes32 digest = b2.mintDigest(lockId, user, ONE_NEV, 100, "tx");
        (uint256 lo, uint256 hi) = _sorted(pk1, pk2);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(lo, digest);
        sigs[1] = _sign(hi, digest);

        vm.expectRevert(NEV369Bridge.MintingDisabled.selector);
        b2.mintFromNEV369(user, ONE_NEV, lockId, "tx", 100, sigs);
    }

    function test_per_mint_cap_bounds_a_single_mint() public {
        uint256 tooBig = 2_000_000 * ONE_NEV;
        bytes32 lockId = keccak256("lock-big");
        bytes[] memory sigs = _sigs(lockId, user, tooBig, 100, "tx", pk1, pk2);

        vm.expectRevert();
        bridge.mintFromNEV369(user, tooBig, lockId, "tx", 100, sigs);
    }

    function test_window_cap_bounds_a_compromised_signer_set() public {
        // Even with the threshold met legitimately, one window's damage
        // is bounded. Losing a window beats losing everything.
        bytes32 a = keccak256("w-0");
        bytes[] memory sa = _sigs(a, user, WINDOW_LIMIT, 100, "tx", pk1, pk2);
        bridge.mintFromNEV369(user, WINDOW_LIMIT, a, "tx", 100, sa);

        bytes32 over = keccak256("w-over");
        bytes[] memory so = _sigs(over, user, ONE_NEV, 100, "tx", pk1, pk2);
        vm.expectRevert();
        bridge.mintFromNEV369(user, ONE_NEV, over, "tx", 100, so);
    }

    function test_window_rolls_after_its_period() public {
        bytes32 a = keccak256("roll-a");
        bytes[] memory sa = _sigs(a, user, WINDOW_LIMIT, 100, "tx", pk1, pk2);
        bridge.mintFromNEV369(user, WINDOW_LIMIT, a, "tx", 100, sa);

        vm.warp(block.timestamp + 24 hours + 1);

        bytes32 b = keccak256("roll-b");
        bytes[] memory sb = _sigs(b, user, ONE_NEV, 100, "tx", pk1, pk2);
        bridge.mintFromNEV369(user, ONE_NEV, b, "tx", 100, sb);
        assertEq(token.balanceOf(user), WINDOW_LIMIT + ONE_NEV);
    }

    // ── Signer set ───────────────────────────────────────────────────

    function test_removing_a_signer_below_threshold_is_refused() public {
        // Otherwise minting bricks until somebody notices, and "the
        // bridge is stuck" is harder to diagnose than a refused removal.
        vm.startPrank(admin);
        bridge.removeSigner(s3);
        vm.expectRevert();
        bridge.removeSigner(s2);
        vm.stopPrank();
    }

    function test_a_removed_signer_can_no_longer_authorize() public {
        vm.prank(admin);
        bridge.removeSigner(s3);

        bytes32 lockId = keccak256("lock-removed");
        bytes[] memory sigs = _sigs(lockId, user, ONE_NEV, 100, "tx", pk1, pk3);

        vm.expectRevert();
        bridge.mintFromNEV369(user, ONE_NEV, lockId, "tx", 100, sigs);
    }

    // ── wNEV ─────────────────────────────────────────────────────────

    function test_bridge_rotation_cannot_skip_the_timelock() public {
        vm.startPrank(admin);
        token.proposeBridge(address(0xD00D));
        vm.expectRevert();
        token.finalizeBridge();
        vm.stopPrank();
    }

    function test_burn_requires_an_allowance() public {
        bytes32 lockId = keccak256("lock-burn");
        bytes[] memory sigs = _sigs(lockId, user, ONE_NEV, 100, "tx", pk1, pk2);
        bridge.mintFromNEV369(user, ONE_NEV, lockId, "tx", 100, sigs);

        vm.prank(user);
        vm.expectRevert();
        bridge.burnToNEV369(ONE_NEV, "nev369-dest");
    }

    function test_two_identical_burns_in_one_block_both_succeed() public {
        bytes32 lockId = keccak256("lock-burns");
        bytes[] memory sigs = _sigs(lockId, user, 10 * ONE_NEV, 100, "tx", pk1, pk2);
        bridge.mintFromNEV369(user, 10 * ONE_NEV, lockId, "tx", 100, sigs);

        vm.startPrank(user);
        token.approve(address(bridge), 10 * ONE_NEV);
        bytes32 b1 = bridge.burnToNEV369(ONE_NEV, "dest");
        bytes32 b2 = bridge.burnToNEV369(ONE_NEV, "dest");
        vm.stopPrank();

        assertTrue(b1 != b2, "burn ids must be unique");
    }

    function test_pausing_the_token_stops_minting() public {
        vm.prank(admin);
        token.pause();

        bytes32 lockId = keccak256("lock-paused");
        bytes[] memory sigs = _sigs(lockId, user, ONE_NEV, 100, "tx", pk1, pk2);
        vm.expectRevert();
        bridge.mintFromNEV369(user, ONE_NEV, lockId, "tx", 100, sigs);
    }

    /// Found by the invariant fuzzer: grantRole bypassed the 48h timelock.
    function test_admin_cannot_grant_bridge_role_directly() public {
        bytes32 role = token.BRIDGE_ROLE();
        vm.prank(admin);
        vm.expectRevert(wNEV.BridgeRoleIsTimelocked.selector);
        token.grantRole(role, admin);

        // ...so the admin can't mint around the bridge either.
        vm.prank(admin);
        vm.expectRevert();
        token.mint(admin, ONE_NEV);
        assertEq(token.totalSupply(), bridge.totalMinted());
    }

    function test_admin_can_still_revoke_a_bridge_at_once() public {
        bytes32 role = token.BRIDGE_ROLE();
        vm.prank(admin);
        token.revokeRole(role, address(bridge));
        assertFalse(token.hasRole(role, address(bridge)));
    }

    // ── Invariant ────────────────────────────────────────────────────

    function invariant_circulating_never_exceeds_total_minted() public view {
        assertLe(token.totalSupply(), bridge.totalMinted());
    }
}
