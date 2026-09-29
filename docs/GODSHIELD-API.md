# GodShield API

Post-quantum security as an HTTP API: find the cryptography a quantum
computer breaks, and verify Dilithium5 signatures.

**Base URL:** `https://q-lock-ecosystem.com/godshield`

## Get a key

1. Go to q-lock-ecosystem.com → **GodShield** → **API access & plans**.
2. Create a free account (100 calls/month) or upgrade to Pro / Enterprise.
3. Press **Show** next to your API key. **Replace key** issues a new one and
   disables the old one immediately.

Send the key on every call:

```
X-API-Key: qlk_…
```

Without a key you get 25 calls per day per IP, for trying it out.

## Endpoints

### `POST /api/v1/scan`: quantum-risk scan (metered)

```bash
curl -X POST https://q-lock-ecosystem.com/godshield/api/v1/scan \
  -H "X-API-Key: $GODSHIELD_KEY" -H "Content-Type: application/json" \
  -d '{"source_code":"const ec = new EC(\"secp256k1\")"}'
```

Returns `vulnerabilities` (each with `crypto_type`, `severity`,
`description`, `recommendation`, `line`), a `migration_plan` and a
`severity_score`. Input limit: 900 KB per call.

### `POST /api/v1/verify`: verify a Dilithium5 signature (metered)

```json
{ "public_key": "<hex, 2592 bytes>", "signature": "<hex>",
  "message": "hello", "encoding": "utf8" }
```

`encoding` is `utf8` (default), `hex` or `base64`. Returns `valid`,
`signer_fingerprint` and `message`. Nothing secret is ever sent: the API
never accepts or holds secret keys.

### Also metered

`POST /api/v1/address/encode`, `POST /api/v1/transaction/build`,
`POST /api/v1/gateway/verify`, `POST /api/v1/gateway/policy/check`

### Free (not metered)

`GET /health` · `GET /api/v1/stats` · `GET /api/v1/chains` ·
`GET /api/v1/gateway/audit` (the hash-linked audit trail; `?since=N` to page)

## Errors

| Code | Meaning |
|---|---|
| 401 | Unknown API key |
| 402 | Quota reached. The body says which, and how to upgrade |
| 429 | Too many requests per second. Slow down and retry |

## Plans

| Plan | Calls / month | Escrow fee |
|---|---|---|
| Free | 100 | 0.30% |
| Pro | 10,000 | 0.20% |
| Enterprise | 250,000 | 0.15% |

Quotas reset on the 1st of each month (UTC). One Q-Lock account covers the
GodShield API and Q-Lock escrow.
