#!/usr/bin/env bash
# Writes chain-spec/nev369-mainnet.env — the four values every NEV369 node
# needs to build the identical genesis block — from a running node and the
# genesis addresses in .env.
#
#   scripts/export-chain-spec.sh [node-url]      (default http://localhost:8080)
#
# Everything written is public: a timestamp, a hash, and two public keys.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - "${1:-http://localhost:8080}" <<'PY'
import json, re, sys, urllib.request
node = sys.argv[1].rstrip('/')
b = json.load(urllib.request.urlopen(node + '/block/0'))
env = open('.env').read()
def get(k):
    m = re.search(rf'^{k}=(.*)$', env, re.M)
    return m.group(1).strip() if m else ''
arch, nev = get('NEV369_ARCHITECT_ADDRESS'), get('NEV369_NEVAEH_VAULT_ADDRESS')
recipients = [t['recipient'] for t in b['transactions']]
assert b['index'] == 0, 'node did not return block 0'
assert recipients == [arch, nev], 'block 0 premine recipients do not match the addresses in .env'
assert len(b['hash']) == 128, 'unexpected genesis hash length'
spec = f"""# NEV369 mainnet chain spec — genesis created {b['timestamp']} (unix seconds).
#
# Copy these four lines into .env UNCHANGED. Every node must build the same
# block 0; a node whose values differ refuses to start rather than silently
# founding a separate chain. All four values are public.
NEV369_GENESIS_TIMESTAMP={b['timestamp']}
NEV369_GENESIS_HASH={b['hash']}
NEV369_ARCHITECT_ADDRESS={arch}
NEV369_NEVAEH_VAULT_ADDRESS={nev}
"""
open('chain-spec/nev369-mainnet.env', 'w').write(spec)
print('chain-spec/nev369-mainnet.env written')
print('  genesis timestamp:', b['timestamp'])
print('  genesis hash:     ', b['hash'][:32] + '…')
PY
