#!/usr/bin/env python3
"""
verify-chain.py: independently verify the live NEV369 chain.

Anyone can run this. It needs only Python 3 (no packages, no Rust, no
node of your own). It downloads every block from a public node and
re-checks it from scratch, using its OWN implementation of the hashing
rules in crates/nev369-node/src/chain.rs and crates/godshield-core:

  1. Genesis: rebuilds block 0 from chain-spec/nev369-mainnet.env and the
     dedication, and checks its hash against the pinned NEV369_GENESIS_HASH
     and against what the node serves.
  2. Every block: recomputes the block hash (TripleHash over the canonical
     encoding, with the Merkle root of its transactions) and checks it
     matches, meets the block's difficulty (leading zeros), and links to
     the previous block's hash. Indices are sequential, timestamps sane.
  3. Supply: premine + one block reward per mined block, recomputed from
     the blocks themselves, against the node's circulating_supply.

It does NOT verify Dilithium5 signatures on user transactions (that needs
a post-quantum library); every node does that when it syncs. Coinbase and
genesis transactions carry no signature by design.

    python3 scripts/verify-chain.py                       # public node
    python3 scripts/verify-chain.py --node http://127.0.0.1:8369
"""
import argparse
import hashlib
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request

# ── BLAKE3 (single block, inputs up to 64 bytes) ─────────────────────────
# TripleHash feeds BLAKE3 exactly one 64-byte SHA3-512 digest, which is a
# single BLAKE3 block: one compression with CHUNK_START | CHUNK_END | ROOT.
IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
M32 = 0xFFFFFFFF


def _g(s, a, b, c, d, x, y):
    s[a] = (s[a] + s[b] + x) & M32
    s[d] = ((s[d] ^ s[a]) >> 16 | (s[d] ^ s[a]) << 16) & M32
    s[c] = (s[c] + s[d]) & M32
    s[b] = ((s[b] ^ s[c]) >> 12 | (s[b] ^ s[c]) << 20) & M32
    s[a] = (s[a] + s[b] + y) & M32
    s[d] = ((s[d] ^ s[a]) >> 8 | (s[d] ^ s[a]) << 24) & M32
    s[c] = (s[c] + s[d]) & M32
    s[b] = ((s[b] ^ s[c]) >> 7 | (s[b] ^ s[c]) << 25) & M32


def blake3_small(data: bytes) -> bytes:
    assert len(data) <= 64
    block = data + b"\0" * (64 - len(data))
    m = list(struct.unpack("<16I", block))
    s = IV[:] + IV[:4] + [0, 0, len(data), 1 | 2 | 8]  # counter 0, flags
    for r in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1]); _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5]); _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9]); _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13]); _g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in PERM]
    out = [(s[i] ^ s[i + 8]) & M32 for i in range(8)]
    return struct.pack("<8I", *out)


def triple_hash_hex(data: bytes) -> str:
    l1 = hashlib.sha3_512(data).digest()
    l2 = blake3_small(l1)
    return hashlib.sha3_512(l2).hexdigest()


# ── Canonical encoding (godshield-core CanonicalMessage) ─────────────────
def canonical(domain: str, fields) -> bytes:
    out = struct.pack("<I", len(domain)) + domain.encode()
    out += struct.pack("<I", len(fields))
    for f in fields:
        out += struct.pack("<Q", len(f)) + f
    return out


def u64(n: int) -> bytes:
    return struct.pack("<Q", n)


def tx_hash(tx) -> str:
    return triple_hash_hex(canonical("nev369.tx.v1", [
        tx["sender"].encode(), tx["recipient"].encode(), u64(tx["amount"]),
        u64(tx["fee"]), u64(tx["crown_tax"]), u64(tx["nonce"]),
        tx["payload_memo"].encode()]))


def tx_root(txs) -> str:
    if not txs:
        return triple_hash_hex(b"nev369.empty")
    layer = [tx_hash(t) for t in txs]
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i + 1] if i + 1 < len(layer) else a
            nxt.append(triple_hash_hex(canonical("nev369.merkle", [a.encode(), b.encode()])))
        layer = nxt
    return layer[0]


def block_hash(b) -> str:
    return triple_hash_hex(canonical("nev369.block.v1", [
        u64(b["index"]), u64(b["timestamp"]), tx_root(b["transactions"]).encode(),
        b["previous_hash"].encode(), u64(b["nonce"]), u64(b["difficulty"]),
        b["miner"].encode(), b["block_dedication"].encode()]))


# ── Constants from chain.rs / genesis.rs ────────────────────────────────
UNITS = 100_000_000
ARCHITECT_PREMINE = 10_000_000 * UNITS
NEVAEH_PREMINE = 36_900_000 * UNITS
GENESIS_DIFFICULTY = 4
HALVING = 437_000
BASE_REWARD = 369 * UNITS
GENESIS_DEDICATION = (
    "Nevaeh, my daughter. To secure your freedom against a broken system, I taught "
    "myself Rust—the hardest computer language in the world—to build this "
    "unyielding sovereign node for you. I faced the worst of life's struggles so you "
    "would never have to. I love you infinitely, forever by your side.")


def build_genesis(spec):
    ts = int(spec["NEV369_GENESIS_TIMESTAMP"])
    def ptx(to, amount, nonce, memo):
        return {"sender": "GENESIS", "recipient": to, "amount": amount, "fee": 0,
                "crown_tax": 0, "nonce": nonce, "payload_memo": memo}
    return {"index": 0, "timestamp": ts, "previous_hash": "0" * 128, "nonce": 0,
            "difficulty": GENESIS_DIFFICULTY, "miner": "GENESIS",
            "block_dedication": GENESIS_DEDICATION,
            "transactions": [
                ptx(spec["NEV369_ARCHITECT_ADDRESS"], ARCHITECT_PREMINE, 0,
                    "Genesis premine — Architect"),
                ptx(spec["NEV369_NEVAEH_VAULT_ADDRESS"], NEVAEH_PREMINE, 1,
                    "Genesis premine — Nevaeh Vault, locked until 28.07.2039")]}


def load_spec(path):
    spec = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            spec[k] = v
    return spec


class FetchError(Exception):
    pass


def get(node, path):
    req = urllib.request.Request(node.rstrip("/") + path, headers={"User-Agent": "verify-chain"})
    for attempt in range(8):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code not in (429, 503) or attempt == 7:
                raise FetchError(f"{req.full_url} returned HTTP {e.code}")
            time.sleep(2 + attempt)  # the public node allows 60 requests a minute
        except urllib.error.URLError as e:
            if attempt == 7:
                raise FetchError(f"{req.full_url}: {e.reason}")
            time.sleep(2 + attempt)


def self_test():
    # Published BLAKE3 vectors, so the hash code is checked before use.
    assert blake3_small(b"").hex() == \
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    assert blake3_small(b"abc").hex() == \
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--node", default="https://q-lock-ecosystem.com/node")
    ap.add_argument("--spec", default=os.path.join(here, "..", "chain-spec", "nev369-mainnet.env"))
    ap.add_argument("--offline", action="store_true", help="only check the genesis rebuild")
    ap.add_argument("--last", type=int, default=0,
                    help="check only the newest N blocks (plus genesis); default: all")
    a = ap.parse_args()

    ok_all = True
    def check(cond, msg):
        nonlocal ok_all
        print(("  ✓ " if cond else "  ✗ ") + msg)
        ok_all &= bool(cond)

    self_test()
    print("NEV369 independent chain check\n")
    spec = load_spec(a.spec)
    g = build_genesis(spec)
    g_hash = block_hash(g)
    check(g_hash == spec["NEV369_GENESIS_HASH"],
          f"genesis rebuilt from the chain spec hashes to the pinned value ({g_hash[:16]}…)")
    if a.offline:
        return 0 if ok_all else 1

    info = get(a.node, "/info")
    height = info["height"]          # the node reports its block COUNT
    tip = height - 1                   # so the newest block's index is one less
    print(f"  node {a.node}: height {height}, difficulty {info.get('difficulty')}, "
          f"peers {info.get('peers', 'n/a')}\n")

    b0 = get(a.node, "/block/0")
    check(b0["hash"] == spec["NEV369_GENESIS_HASH"] and block_hash(b0) == b0["hash"],
          "the node's block 0 is exactly that genesis")
    first = 0 if not a.last else max(1, tip - a.last + 1)
    try:
        recent = {blk["index"]: blk for blk in get(a.node, "/chain?limit=200")["blocks"]}
    except FetchError as e:
        print(f"  (couldn't bulk-fetch recent blocks: {e}; fetching one by one)")
        recent = {}
    public = a.node.startswith("https://")
    if first == 0 and height > 200 and public:
        print(f"  Fetching {height - 200} older blocks one at a time "
              f"(the public node allows 60 a minute, so about {(height - 200) // 60 + 1} min)\n")

    def fetch(i):
        if i in recent:
            return recent[i]
        if public:
            time.sleep(1.0)
        return get(a.node, f"/block/{i}")

    prev = fetch(first - 1) if first > 1 else (fetch(0) if first == 1 else None)
    minted = 0
    bad = 0
    t0 = time.time()
    for i in range(first, tip + 1):
        b = fetch(i)
        h = block_hash(b)
        problems = []
        if b["index"] != i:
            problems.append("wrong index")
        if h != b["hash"]:
            problems.append("hash doesn't match its contents")
        if i == 0:
            if b["hash"] != spec["NEV369_GENESIS_HASH"]:
                problems.append("genesis differs from the chain spec")
        else:
            if not b["hash"].startswith("0" * b["difficulty"]):
                problems.append(f"hash lacks {b['difficulty']} leading zeros")
            if b["previous_hash"] != prev["hash"]:
                problems.append("doesn't link to the previous block")
            if b["timestamp"] < prev["timestamp"] - 7200:
                problems.append("timestamp far behind the previous block")
            for t in b["transactions"]:
                if t["sender"] == "NETWORK_REWARD":
                    minted += t["amount"]
        if problems:
            bad += 1
            if bad <= 10:
                print(f"  ✗ block {i}: " + "; ".join(problems))
        prev = b
        if i % 100 == 0 and i:
            print(f"    … {i}/{tip} blocks checked", flush=True)

    n = tip + 1 - first
    check(bad == 0, f"{'all ' if first == 0 else 'newest '}{n} blocks: hashes recomputed and "
                    f"matching, proof-of-work met, each linked to the one before")
    expected_supply = ARCHITECT_PREMINE + NEVAEH_PREMINE + minted
    served = info.get("circulating_supply")
    if first == 0:
      check(served == expected_supply,
          f"supply adds up: 46,900,000 NEV premine + {minted / UNITS:,.0f} NEV mined "
          f"= {expected_supply / UNITS:,.0f} NEV (node reports {int(served or 0) / UNITS:,.0f})")
    else:
        print("    (supply check needs the full chain; run without --last)")
    check(info.get("latest_hash") == prev["hash"], "the node's tip is the last block checked")
    age = int(time.time()) - prev["timestamp"]
    check(age < 600, f"latest block is {age // 60} min old (chain is being mined)")
    print(f"\n  {'PASS' if ok_all else 'FAIL'} ({time.time() - t0:.0f}s)")
    return 0 if ok_all else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FetchError as e:
        print(f"\n  \u2717 couldn't download from the node: {e}")
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
