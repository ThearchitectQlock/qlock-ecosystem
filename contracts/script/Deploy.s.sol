// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {wNEV} from "../src/wNEV.sol";
import {NEV369Bridge} from "../src/NEV369Bridge.sol";

/**
 * Deployment is NOT a single transaction, and nothing in v2 said so.
 *
 * The bridge cannot grant itself BRIDGE_ROLE — only wNEV's admin can,
 * through propose → 48h → finalize. Then minting is still disabled until
 * the admin sets a window limit, which is itself a 48-hour timelocked
 * raise from zero.
 *
 * So a correct mainnet bring-up is four steps over at least 96 hours:
 *
 *   Stage 1  deploy wNEV and NEV369Bridge, propose the bridge role
 *   Stage 2  (+48h) finalize the bridge role, propose the mint limit
 *   Stage 3  (+48h) finalize the mint limit
 *   Stage 4  verify on-chain state before anyone bridges anything
 *
 * Discovering that sequence after deploying is how a launch ends up with
 * a live token nobody can mint against, and an admin improvising under
 * time pressure.
 *
 * Run:
 *   forge script script/Deploy.s.sol:Stage1 --rpc-url $RPC --broadcast
 *   forge script script/Deploy.s.sol:Stage2 --rpc-url $RPC --broadcast
 *   forge script script/Deploy.s.sol:Stage3 --rpc-url $RPC --broadcast
 *   forge script script/Deploy.s.sol:Verify --rpc-url $RPC
 */

// ═══════════════════════════════════════════════════════════════════════

contract Stage1 is Script {
    function run() external {
        address admin = vm.envAddress("BRIDGE_ADMIN");

        // ADMIN MUST BE A MULTISIG. A single EOA here means one key can
        // rotate the bridge and mint to the window limit. The 48-hour
        // delays only help if someone other than the attacker is
        // watching and able to act.
        require(admin.code.length > 0, "Deploy: admin must be a contract (multisig)");

        // Signer set, comma-separated in BRIDGE_SIGNERS.
        //
        // Independence is the whole property: separate keys, on separate
        // infrastructure, operated by separate people. Five keys in one
        // process is a threshold on paper and one key in practice.
        address[] memory signers = vm.envAddress("BRIDGE_SIGNERS", ",");
        uint256 threshold = vm.envUint("BRIDGE_THRESHOLD");

        require(signers.length >= 3, "Deploy: at least 3 signers");
        require(threshold >= 2, "Deploy: threshold of 1 is the single-key model");
        require(threshold <= signers.length, "Deploy: threshold exceeds signer count");

        vm.startBroadcast();

        wNEV token = new wNEV(admin);
        NEV369Bridge bridge = new NEV369Bridge(address(token), admin, signers, threshold);

        vm.stopBroadcast();

        console2.log("wNEV          ", address(token));
        console2.log("signers       ", signers.length);
        console2.log("threshold     ", threshold);
        console2.log("NEV369Bridge  ", address(bridge));
        console2.log("");
        console2.log("NEXT, from the admin multisig:");
        console2.log("  wNEV.proposeBridge(%s)", address(bridge));
        console2.log("  wait 48 hours, then run Stage2");
        console2.log("");
        console2.log("Minting is DISABLED until a window limit is set.");
        console2.log("That is intentional.");
    }
}

// ═══════════════════════════════════════════════════════════════════════

contract Stage2 is Script {
    function run() external {
        wNEV token = wNEV(vm.envAddress("WNEV_ADDRESS"));
        address bridge = vm.envAddress("BRIDGE_ADDRESS");
        uint256 windowLimit = vm.envUint("MINT_LIMIT_PER_WINDOW");

        require(token.pendingBridge() == bridge, "Stage2: pending bridge mismatch");
        require(block.timestamp >= token.pendingBridgeEta(), "Stage2: timelock not elapsed");

        // Sanity-check the limit against something real rather than
        // against the cap, which does not bind. NEV369's terminal supply
        // is roughly 67.9M NEV; a 24h window limit anywhere near that is
        // not a limit.
        require(windowLimit > 0, "Stage2: zero limit disables the bridge");
        require(
            windowLimit <= 5_000_000 * 1e8,
            "Stage2: window limit above 5M NEV/day - that is ~7% of terminal supply "
            "in a single day. If that is genuinely intended, remove this guard "
            "deliberately and record why."
        );

        vm.startBroadcast();
        token.finalizeBridge();
        NEV369Bridge(bridge).proposeMintLimit(windowLimit);
        vm.stopBroadcast();

        console2.log("BRIDGE_ROLE granted to %s", bridge);
        console2.log("Mint limit proposed: %s base units", windowLimit);
        console2.log("Wait 48 hours, then run Stage3.");
    }
}

// ═══════════════════════════════════════════════════════════════════════

contract Stage3 is Script {
    function run() external {
        NEV369Bridge bridge = NEV369Bridge(vm.envAddress("BRIDGE_ADDRESS"));

        require(bridge.pendingMintLimitEta() != 0, "Stage3: nothing pending");
        require(block.timestamp >= bridge.pendingMintLimitEta(), "Stage3: timelock not elapsed");

        vm.startBroadcast();
        bridge.finalizeMintLimit();
        vm.stopBroadcast();

        console2.log("Mint limit active: %s", bridge.mintLimitPerWindow());
        console2.log("Run Verify before announcing anything.");
    }
}

// ═══════════════════════════════════════════════════════════════════════

contract Verify is Script {
    function run() external view {
        wNEV token = wNEV(vm.envAddress("WNEV_ADDRESS"));
        NEV369Bridge bridge = NEV369Bridge(vm.envAddress("BRIDGE_ADDRESS"));
        address admin = vm.envAddress("BRIDGE_ADMIN");

        console2.log("-- wNEV --");
        console2.log("decimals            ", token.decimals());
        console2.log("totalSupply         ", token.totalSupply());
        console2.log("MAX_SUPPLY          ", token.MAX_SUPPLY());
        console2.log("currentBridge       ", token.currentBridge());
        console2.log("paused              ", token.paused());
        console2.log("pendingBridge       ", token.pendingBridge());

        console2.log("");
        console2.log("-- NEV369Bridge --");
        console2.log("wnev                ", address(bridge.wnev()));
        console2.log("totalMinted         ", bridge.totalMinted());
        console2.log("mintLimitPerWindow  ", bridge.mintLimitPerWindow());
        console2.log("remainingInWindow   ", bridge.remainingInWindow());
        console2.log("paused              ", bridge.paused());

        console2.log("");
        console2.log("-- Checks --");

        _check(token.decimals() == 8, "decimals == 8 (matches NEV369 base units)");
        _check(token.currentBridge() == address(bridge), "wNEV points at this bridge");
        _check(token.hasRole(token.BRIDGE_ROLE(), address(bridge)), "bridge holds BRIDGE_ROLE");
        _check(token.pendingBridge() == address(0), "no dangling pending bridge");
        _check(bridge.mintLimitPerWindow() > 0, "mint limit is set");
        _check(bridge.signerThreshold() >= 2, "threshold is at least 2");
        _check(bridge.signerCount() >= bridge.signerThreshold(), "enough signers for threshold");
        _check(token.hasRole(token.DEFAULT_ADMIN_ROLE(), admin), "admin holds DEFAULT_ADMIN_ROLE");
        _check(admin.code.length > 0, "admin is a contract (multisig)");
        _check(
            !token.hasRole(token.DEFAULT_ADMIN_ROLE(), address(bridge)),
            "bridge does NOT hold admin role"
        );
        _check(token.MAX_SUPPLY() == bridge.MAX_SUPPLY(), "supply caps agree");

        console2.log("");
        console2.log("NOT CHECKED HERE, and still blocking:");
        console2.log("  - no independent audit of either contract");
        console2.log("  - the bridge is trusted: mintFromNEV369 has no proof");
        console2.log("    that a lock happened on NEV369");
        console2.log("  - NEV369 has an open critical consensus bug (NEV-001)");
        console2.log("    that lets a block mint from nothing. A bridge on top");
        console2.log("    of that inherits it.");
    }

    function _check(bool ok, string memory what) internal pure {
        console2.log(ok ? "  [ok]   " : "  [FAIL] ", what);
    }
}
