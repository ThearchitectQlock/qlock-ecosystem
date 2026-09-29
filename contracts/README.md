# NEV369 EVM contracts

`wNEV.sol` — wrapped NEV, **8 decimals** (1 NEV locked = 1 wNEV minted).
`NEV369Bridge.sol` — mints wNEV only on an **m-of-n EIP-712 threshold** of
independent signers.

## Build and test

    cp .env.example .env
    forge install OpenZeppelin/openzeppelin-contracts@v5.0.2 --no-git
    forge install foundry-rs/forge-std --no-git
    forge build && forge test -vvv
    FOUNDRY_PROFILE=ci forge test        # heavier fuzzing + invariants

OpenZeppelin is pinned to **v5.0.2** exactly (`utils/Pausable`,
`utils/ReentrancyGuard`).

## How a mint is authorized

`mintFromNEV369(user, amount, lockId, sourceTx, sourceBlockHeight, signatures)`

1. Each signer signs the EIP-712 `MintAuthorization(bytes32 lockId, address
   recipient, uint256 amount, uint256 sourceBlockHeight, string sourceTx)`
   under the domain `EIP712("NEV369Bridge", "1")`. `mintDigest(...)` returns
   the exact digest.
2. Signatures are passed sorted by **strictly ascending signer address**, which
   makes a duplicate signer impossible.
3. The contract recovers every signature, requires each signer to be
   registered, and requires at least `signerThreshold` of them.
4. Each `lockId` mints once. Minting stays disabled until a per-window limit is
   set, and every mint is bounded by it.

The caller is irrelevant — the signatures authorize. `nev369-submitter` sends the
transaction with a gas-only key; `nev369-relayer` collects the signatures and
holds no key at all.

Signer management: `addSigner`, `removeSigner` (refuses to go below the
threshold), `setThreshold` (≥ 2, ≤ signer count).

## Deploy

Four stages over at least 96 hours, because of two 48-hour timelocks:

    forge script script/Deploy.s.sol:Stage1 --rpc-url $SEPOLIA_RPC_URL --broadcast
    # +48h
    forge script script/Deploy.s.sol:Stage2 --rpc-url $SEPOLIA_RPC_URL --broadcast
    # +48h
    forge script script/Deploy.s.sol:Stage3 --rpc-url $SEPOLIA_RPC_URL --broadcast
    forge script script/Deploy.s.sol:Verify --rpc-url $SEPOLIA_RPC_URL

Stage 1 requires `BRIDGE_SIGNERS` (≥ 3 addresses) and `BRIDGE_THRESHOLD` (≥ 2).
The Verify stage reads the deployed state back and checks the signer set, threshold,
roles and limits before anyone bridges anything. Put the deployed
`BRIDGE_ADDRESS` and the chain id into the root `.env` so the coordinator
computes the same EIP-712 domain.
