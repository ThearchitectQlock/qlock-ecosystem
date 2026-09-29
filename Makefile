# ═══════════════════════════════════════════════════════════════════════
# Q-Lock — developer and operator entrypoints
#
# The README and docs/nevaeh-vault-ceremony.md both reference targets in
# this file by name (`make verify && make build && make up`,
# `make vault-nevaeh-xrpl`). They did not exist. They do now.
#
# `make verify` is the gate. It runs everything CI runs, so a green local
# verify means a green pipeline.
# ═══════════════════════════════════════════════════════════════════════

.DEFAULT_GOAL := help
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

COMPOSE := docker compose
CARGO   := cargo

# ── Help ───────────────────────────────────────────────────────────────

.PHONY: help
help:
	@echo ""
	@echo "  Q-Lock — make targets"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ── Verification ───────────────────────────────────────────────────────

.PHONY: verify
verify: fmt-check clippy test audit guard ## Run everything CI runs. The gate.
	@echo ""
	@echo "  ✓ verify passed"
	@echo ""
	@echo "  NOTE: this does not mean the system is production-ready."
	@echo "  See the Production readiness gate in README.md — NEV-001 is open."
	@echo ""

.PHONY: fmt
fmt: ## Format the workspace
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Fail if formatting is off
	$(CARGO) fmt --all -- --check

.PHONY: clippy
clippy: ## Lint with warnings as errors
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

.PHONY: test
test: ## Run the workspace test suite
	$(CARGO) test --workspace --all-features

.PHONY: test-release
test-release: ## Run tests optimised (Dilithium5 is slow in debug)
	$(CARGO) test --workspace --release

.PHONY: audit
audit: ## Check dependencies for known advisories
	@command -v cargo-audit >/dev/null 2>&1 || $(CARGO) install cargo-audit --locked
	$(CARGO) audit

.PHONY: guard
guard: ## Regression guards for previously-exploitable bugs
	@bash scripts/security-guard.sh

# ── Build ──────────────────────────────────────────────────────────────

.PHONY: build
build: ## Release build of the whole workspace
	$(CARGO) build --release --workspace

.PHONY: build-images
build-images: ## Build every Docker image (node, escrow, bridge, godshield)
	$(COMPOSE) --profile bridge --profile godshield build

.PHONY: lockfile
lockfile: ## Generate Cargo.lock (commit it — the images build --locked)
	$(CARGO) generate-lockfile

# ── Local stack ────────────────────────────────────────────────────────

.PHONY: up
up: check-env ## Start the full local stack
	$(COMPOSE) up -d
	@echo ""
	@echo "  escrow API     http://localhost:3000/health"
	@echo "  nev369 node-1  http://localhost:8080/health"
	@echo "  nev369 node-2  http://localhost:8081/health"
	@echo "  prometheus     http://localhost:9090"
	@echo "  grafana        http://localhost:3001"
	@echo "  console        http://localhost/          (via nginx)"
	@echo "  explorer       http://localhost/explorer/"
	@echo ""
	@echo "  Watch the two nodes gossip:  make logs-nodes"
	@echo "  Optional:  make up-bridge   make up-godshield   make cluster"
	@echo ""

.PHONY: up-bridge
up-bridge: check-env ## Start the ETH bridge coordinator + submitter
	$(COMPOSE) --profile bridge up -d

.PHONY: up-godshield
up-godshield: check-env ## Start the GodShield API and PQ Security Gateway
	$(COMPOSE) --profile godshield up -d

.PHONY: cluster
cluster: ## Three-node NEV369 consensus cluster (ports 8181-8183)
	docker compose -f docker-compose.nev369.yml up -d --build

.PHONY: inheritance
inheritance: ## Inheritance escrow ceremony — prints usage
	$(CARGO) run --release -p qlock-escrow --bin qlock-inheritance -- --help

.PHONY: down
down: ## Stop the stack, keep volumes
	$(COMPOSE) down

.PHONY: nuke
nuke: ## Stop the stack and DESTROY all chain and database data
	@echo "This deletes the sled chain directories and the Postgres volume."
	@read -p "Type 'destroy' to confirm: " c && [ "$$c" = "destroy" ]
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail all logs
	$(COMPOSE) logs -f

.PHONY: logs-nodes
logs-nodes: ## Tail just the two NEV369 nodes
	$(COMPOSE) logs -f nev369-node-1 nev369-node-2

.PHONY: ps
ps: ## Show container status and health
	$(COMPOSE) ps

# ── Database ───────────────────────────────────────────────────────────

.PHONY: db-migrate
db-migrate: ## Apply Postgres migrations
	$(COMPOSE) exec -T postgres psql -U qlock -d qlock < db/schema.sql

.PHONY: db-shell
db-shell: ## Open a psql shell
	$(COMPOSE) exec postgres psql -U qlock -d qlock

# ── Environment ────────────────────────────────────────────────────────

.PHONY: check-env
check-env: ## Verify .env exists and has no placeholder values left
	@test -f .env || { echo "ERROR: no .env — run: cp .env.example .env"; exit 1; }
	@if grep -qE '^JWT_SECRET=\s*$$' .env; then \
		echo "ERROR: JWT_SECRET is empty in .env — openssl rand -hex 32"; exit 1; fi
	@if grep -qE '^(DB_PASSWORD|REDIS_PASSWORD)=change-me' .env; then \
		echo "WARNING: DB_PASSWORD / REDIS_PASSWORD are still the example values."; fi
	@if grep -q '^QLOCK_ATTESTATION_VAULT=..*' .env; then \
		echo "ERROR: QLOCK_ATTESTATION_VAULT is set. The escrow backend panics"; \
		echo "       deliberately when it sees this — a vault that unlocks itself"; \
		echo "       unattended is not protecting anything. Recover with"; \
		echo "       'godshield vault recover' and inject the key via your"; \
		echo "       secrets manager instead."; exit 1; fi
	@if grep -qE '^NEV369_(ARCHITECT|NEVAEH_VAULT)_ADDRESS=(ARCHITECT_SOVEREIGN_KEY_01|NEVAEH_NEV369_SOVEREIGN_VAULT)$$' .env; then \
		echo "WARNING: premine addresses are still the placeholder strings."; \
		echo "         Fine for local development — the premine is unspendable"; \
		echo "         because no key maps to those literals. The node refuses"; \
		echo "         to boot with these when NEV369_ENV=production."; fi

# ── Vault ceremony ─────────────────────────────────────────────────────
#
# READ docs/nevaeh-vault-ceremony.md IN FULL BEFORE RUNNING ANY OF THESE.
# Do it on a machine you trust, offline, not streaming, with guardians
# already chosen and contactable.

.PHONY: vault-warning
vault-warning:
	@echo ""
	@echo "  ┌─────────────────────────────────────────────────────────┐"
	@echo "  │  VAULT CEREMONY                                         │"
	@echo "  │                                                         │"
	@echo "  │  Offline machine. No screen recording. No streaming.    │"
	@echo "  │  Guardians chosen and contactable. Physical storage     │"
	@echo "  │  ready for each share.                                  │"
	@echo "  │                                                         │"
	@echo "  │  This is much harder to fix later than to do right now. │"
	@echo "  │  Read docs/nevaeh-vault-ceremony.md first.              │"
	@echo "  └─────────────────────────────────────────────────────────┘"
	@echo ""
	@read -p "  Type 'ready' to continue: " c && [ "$$c" = "ready" ]

.PHONY: vault-architect
vault-architect: vault-warning ## Architect wallet vault — 2-of-3, no timelock
	godshield vault create \
	  --label architect-wallet \
	  --threshold 2 --shares 3 \
	  --output ./architect_vault.json \
	  --shares-dir ./architect_shares/

.PHONY: vault-nevaeh-nev369
vault-nevaeh-nev369: vault-warning ## Nevaeh NEV369 premine vault — 3-of-5, locked to 2039
	godshield vault create \
	  --label nevaeh-nev369 \
	  --beneficiary "Nevaeh" --dob 2021-07-28 --unlock 2039-07-28 \
	  --threshold 3 --shares 5 \
	  --output ./nevaeh_nev369_vault.json \
	  --shares-dir ./nevaeh_nev369_shares/

.PHONY: vault-nevaeh-xrpl
vault-nevaeh-xrpl: vault-warning ## XRPL seed vault — 3-of-5, THE ACTUAL INHERITANCE
	@echo ""
	@echo "  This vault holds the key to the real inheritance."
	@echo ""
	@echo "  Generate the XRPL account in a real wallet (Xaman or hardware)"
	@echo "  FIRST. Not here, not in any code from this repository, and never"
	@echo "  by pasting the seed into an AI assistant."
	@echo ""
	@echo "  Fund the address with at least the base reserve before 2039, or"
	@echo "  EscrowFinish fails with tecNO_DST and the funds are unreleasable."
	@echo "  That mistake is permanent."
	@echo ""
	@read -p "  XRPL account created, funded and explorer-verified? (yes): " c && [ "$$c" = "yes" ]
	godshield vault create \
	  --label nevaeh-xrpl-seed \
	  --beneficiary "Nevaeh" --dob 2021-07-28 --unlock 2039-07-28 \
	  --threshold 3 --shares 5 \
	  --guardian "You:contact:Home safe" \
	  --guardian "Family:contact:Their home" \
	  --guardian "Friend:contact:Different city" \
	  --guardian "Bank:details:Safe deposit box" \
	  --guardian "Solicitor:details:Held with will" \
	  --output ./nevaeh_xrpl_vault.json \
	  --shares-dir ./nevaeh_xrpl_shares/
	@echo ""
	@echo "  NEXT, and do not skip it:"
	@echo "    1. Create the XRPL escrow with FinishAfter = 2039-07-28"
	@echo "    2. Record Owner AND OfferSequence into the vault notes, the"
	@echo "       ceremony doc, and your will. OfferSequence is the single"
	@echo "       most losable value in this entire design."
	@echo "    3. Test recovery twice with different share combinations"
	@echo "    4. Distribute shares physically, never electronically"
	@echo "    5. rm -rf ./nevaeh_xrpl_shares/ once distributed"
	@echo "    6. Set the annual calendar reminder"
	@echo ""

.PHONY: vault-verify-all
vault-verify-all: ## Annual maintenance — integrity check every vault file
	@for v in ./*_vault.json; do \
		[ -e "$$v" ] || continue; \
		echo "── $$v"; godshield vault verify --vault "$$v"; \
	done

# ── Housekeeping ───────────────────────────────────────────────────────

.PHONY: clean
clean: ## Remove build artefacts
	$(CARGO) clean

.PHONY: scan
scan: ## Scan the workspace for quantum-vulnerable primitives
	# One invocation. The CLI previously took a single file, so this
	# target had to loop with `find` — godshield-scanner walks trees now.
	godshield scan . --migrate
	@echo ""
	@echo "  Identifier matching. A clean scan is not a clean bill of health —"
	@echo "  it cannot see crypto reached through dependencies, dynamic"
	@echo "  dispatch, FFI, or runtime algorithm selection."
	@echo ""

.PHONY: scan-gate
scan-gate: ## Fail if any CRITICAL primitive is found (for CI)
	godshield scan . --fail-on critical
