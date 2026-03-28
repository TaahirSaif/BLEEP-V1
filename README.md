<div align="center">

<img src="https://www.bleepecosystem.com/logo.png" alt="BLEEP Logo" width="120" />

# BLEEP Ecosystem

**Self-Healing · Quantum-Secure · AI-Native Blockchain**

[![Build & Test](https://github.com/bleep-project/bleep/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/bleep-project/bleep/actions/workflows/build-and-test.yml)
[![Security Audit](https://github.com/bleep-project/bleep/actions/workflows/security.yml/badge.svg)](https://github.com/bleep-project/bleep/actions/workflows/security.yml)
[![Code Quality](https://github.com/bleep-project/bleep/actions/workflows/code-quality.yml/badge.svg)](https://github.com/bleep-project/bleep/actions/workflows/code-quality.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust Edition](https://img.shields.io/badge/Rust-2021%20Edition-orange.svg)](https://www.rust-lang.org)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](Cargo.toml)

*A next-generation blockchain operating system built for the AI era — quantum-resistant, self-governing, and environmentally sustainable.*

[Website](https://www.bleepecosystem.com) · [Whitepaper](docs/BLEEP_Whitepaper.pdf) · [Documentation](#documentation) · [Roadmap](#roadmap) · [Contributing](CONTRIBUTING.md)

</div>


---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Workspace Crates](#workspace-crates)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Building from Source](#building-from-source)
  - [Running a Node](#running-a-node)
  - [Configuration](#configuration)
- [Core Modules](#core-modules)
  - [Consensus Engine](#consensus-engine)
  - [Self-Healing Orchestrator](#self-healing-orchestrator)
  - [Post-Quantum Cryptography](#post-quantum-cryptography)
  - [Dynamic Sharding](#dynamic-sharding)
  - [BLEEP VM](#bleep-vm)
  - [Governance](#governance)
  - [BLEEP Connect](#bleep-connect)
  - [Tokenomics (BLP)](#tokenomics-blp)
- [Testing](#testing)
- [Benchmarks](#benchmarks)
- [Roadmap](#roadmap)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

BLEEP is a post-blockchain operating system designed from first principles to meet the demands of the AI-native, post-quantum world. It replaces the static assumptions of legacy Layer 1 chains with a living, adaptive network where intelligence, computation, and economic coordination merge in a single coherent ecosystem.

BLEEP is written entirely in **Rust** for memory safety and performance, structured as a multi-crate workspace with 19 purpose-built subsystem crates. Its architecture enforces a strict principle throughout: **safety over liveness** — the network will stall rather than diverge.

```
Traditional Blockchain:     BLEEP:
─────────────────────────   ────────────────────────────────────
Static consensus rules   →  Adaptive multi-mode consensus
Manual hard forks        →  Self-amending governance
Vulnerable to quantum    →  Kyber1024 + SPHINCS+ post-quantum
Isolated ecosystem       →  BLEEP Connect cross-chain engine
Fixed governance         →  AI-advisory + ZK-private voting
Single-threaded state    →  Dynamic sharding (AI load-balanced)
```

> **Current Status:** BLEEP V1 is in active development. Core layers (consensus, cryptography, governance, sharding, VM) are substantively implemented. Cross-chain integration and AI inference are in progress. See the [Roadmap](#roadmap) for details.

---

## Key Features

| Feature | Description |
|---|---|
| **Adaptive Consensus** | Dynamically switches between Proof of Stake, PBFT, and Proof of Work based on real-time network conditions |
| **Self-Healing** | Autonomous incident detection, classification, and recovery pipeline — no manual intervention required |
| **Post-Quantum Security** | Kyber1024 KEM + SPHINCS+ signatures + AES-256-GCM hybrid encryption, resistant to quantum attack |
| **AI-Advisory Intelligence** | ONNX-based deterministic ML inference with governance-approval gating; AI recommends, governance decides |
| **Dynamic Sharding** | AI-predicted load balancing across shards with cross-shard 2PC atomicity and self-healing fault recovery |
| **BLEEP VM** | WASM-based smart contract execution via Wasmer with strict gas metering, replay protection, and ZK proof hints |
| **ZK-Private Governance** | Groth16/BLS12-381 zero-knowledge ballots, double-vote prevention, forkless protocol upgrades |
| **BLEEP Connect** | Cross-chain interoperability engine with adapters for Ethereum, Solana, Polkadot, Cosmos, Bitcoin, and more |
| **Constitutional Tokenomics** | 200M BLP hard cap, hash-committed supply state, dynamic fee market, validator slashing |
| **Energy Efficient** | Hybrid PoS-dominant consensus eliminates wasteful proof-of-work under normal conditions |

---

## Architecture

BLEEP is organised into five conceptual layers:

```
┌──────────────────────────────────────────────────────────────────────┐
│                        APPLICATION LAYER                             │
│           dApps · BLEEPat Tokens · Wallets · CLI · RPC              │
├──────────────────────────────────────────────────────────────────────┤
│                         SERVICES LAYER                               │
│       Governance · Compliance · Identity · Telemetry · Indexer       │
├──────────────────────────────────────────────────────────────────────┤
│                         CONTRACT LAYER                               │
│          BLEEP VM (WASM/Wasmer) · Gas Metering · ZK Proofs           │
├──────────────────────────────────────────────────────────────────────┤
│                         NETWORK LAYER                                │
│    Dynamic Sharding · BLEEP Connect · P2P (libp2p) · Dark Routing    │
├──────────────────────────────────────────────────────────────────────┤
│                           CORE LAYER                                 │
│  Consensus (PoS/PBFT/PoW) · Self-Healing · PQ Crypto · Tokenomics   │
└──────────────────────────────────────────────────────────────────────┘
```

**AI flows through every layer as an advisory system.** The `bleep-ai` crate generates signed, deterministic assessments (anomaly scores, governance recommendations, load predictions) that feed into governance decisions. AI cannot unilaterally execute protocol changes — this is a deliberate safety invariant.

---

## Workspace Crates

```
crates/
├── bleep-core          # Block, transaction, mempool, rollback engine
├── bleep-consensus     # PoS / PBFT / PoW engines, self-healing orchestrator
├── bleep-crypto        # Post-quantum crypto, Merkle trees, ZKP verification
├── bleep-governance    # Proposals, ZK voting, forkless upgrades, constitution
├── bleep-economics     # Tokenomics, fee market, validator incentives, oracle bridge
├── bleep-state         # Dynamic sharding, shard lifecycle, cross-shard 2PC
├── bleep-vm            # WASM execution engine, gas metering, smart contracts
├── bleep-ai            # AI decision module, deterministic ONNX inference
├── bleep-interop       # BLEEP Connect, cross-chain adapters, liquidity pools
├── bleep-p2p           # libp2p networking, gossip, peer management, dark routing
├── bleep-pat           # Programmable Asset Tokens (BLEEPat)
├── bleep-zkp           # Zero-knowledge proof library (Groth16 / ark-works)
├── bleep-rpc           # HTTP/WebSocket RPC API (Warp)
├── bleep-wallet-core   # Key management and signing
├── bleep-auth          # Authentication (in progress)
├── bleep-scheduler     # Async task scheduling
├── bleep-telemetry     # Metrics, tracing, observability
├── bleep-indexer       # Block and transaction indexer
└── bleep-cli           # Command-line interface (clap)
```

---

## Getting Started

### Prerequisites

Ensure the following are installed before building BLEEP:

| Dependency | Minimum Version | Notes |
|---|---|---|
| [Rust](https://rustup.rs) | 1.75+ | Install via `rustup` |
| [Clang](https://releases.llvm.org) | 14+ | Required for `clang-sys` bindings |
| [RocksDB](https://rocksdb.org) | 8.x | System library for persistent storage |
| [CMake](https://cmake.org) | 3.20+ | Required for some native crate builds |
| [libssl-dev](https://www.openssl.org) | 1.1+ | TLS support |

**macOS:**
```bash
brew install cmake llvm rocksdb openssl
export LIBRARY_PATH="$(brew --prefix)/lib:$LIBRARY_PATH"
```

**Ubuntu / Debian:**
```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake clang libclang-dev \
  librocksdb-dev libssl-dev pkg-config
```

**Arch Linux:**
```bash
sudo pacman -S base-devel cmake clang rocksdb openssl
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/bleep-project/bleep.git
cd bleep

# Build all crates (release profile)
cargo build --release

# Build with post-quantum cryptography enabled (recommended)
cargo build --release --features quantum

# Build for testnet
cargo build --release --features testnet
```

The compiled binaries will be available at:
```
target/release/bleep          # Main node binary
target/release/bleep_admin    # Admin CLI binary
```

### Running a Node

**Testnet (recommended for development):**
```bash
./target/release/bleep \
  --config config/testnet_config.json \
  --data-dir ~/.bleep/testnet \
  --log-level info
```

**Mainnet:**
```bash
./target/release/bleep \
  --config config/mainnet_config.json \
  --data-dir ~/.bleep/mainnet \
  --log-level warn
```

**Docker:**
```bash
docker pull bleepecosystem/bleep:latest

docker run -d \
  --name bleep-node \
  -v ~/.bleep:/data \
  -p 30333:30333 \
  -p 9933:9933 \
  bleepecosystem/bleep:latest \
  --config /data/config.json
```

### Configuration

BLEEP uses JSON configuration files. Key parameters:

```json
// config/mainnet_config.json (excerpt)
{
  "network": {
    "chain_id": 1,
    "listen_address": "0.0.0.0:30333",
    "bootstrap_peers": ["peer1.bleepecosystem.com:30333"]
  },
  "consensus": {
    "mode": "adaptive",
    "epoch_duration_ms": 6000,
    "validator_threshold": 0.67
  },
  "sharding": {
    "initial_shards": 16,
    "max_shards": 1024,
    "ai_rebalance_enabled": true
  },
  "quantum": {
    "enabled": true,
    "kem_algorithm": "kyber1024",
    "signature_algorithm": "sphincs-sha2-256s"
  }
}
```

A full configuration reference is available in [`docs/configuration.md`](docs/configuration.md).

---

## Core Modules

### Consensus Engine

BLEEP's adaptive consensus dynamically transitions between three modes:

```
Network healthy + high participation  →  Proof of Stake (PoS)
High-value tx / governance finality   →  PBFT
Network instability / attack detected →  Proof of Work (fallback)
```

All mode transitions are gated through the AI advisory module and confirmed by the validator set. The `ConsensusEngine` trait enforces determinism: identical state always produces identical results.

```rust
// crates/bleep-consensus/src/engine.rs
pub trait ConsensusEngine: Send + Sync {
    fn verify_block(&self, block: &Block, state: &BlockchainState)
        -> Result<(), ConsensusError>;
    fn propose_block(&self, state: &BlockchainState, epoch: &EpochState)
        -> Result<Block, ConsensusError>;
    fn finalize_epoch(&self, epoch: &EpochState)
        -> Result<(), ConsensusError>;
}
```

### Self-Healing Orchestrator

The self-healing pipeline runs continuously across all nodes:

```
1. IncidentDetector     →  Identifies anomalies (validator failures, forks, attacks)
2. Classification       →  Healthy / Degraded / Anomalous / Critical
3. RecoveryController   →  Executes deterministic recovery action
4. HealingCycle log     →  Immutable, auditable record of every action taken
```

All validators execute the same recovery deterministically, ensuring the healed state is consistent across the network. Safety is always preferred over liveness: the network stalls rather than produces a divergent state.

### Post-Quantum Cryptography

BLEEP implements NIST-standardised post-quantum algorithms via the `bleep-crypto` crate:

| Algorithm | Use Case | Key Sizes |
|---|---|---|
| **Kyber1024** | Key Encapsulation (KEM) | PK: 1568 B · SK: 3168 B · CT: 1568 B |
| **SPHINCS+-SHA2-256s** | Digital Signatures | PK: 64 B · SK: 128 B · Sig: 29,792 B |
| **AES-256-GCM** | Symmetric encryption (hybrid with Kyber) | Key: 32 B · Nonce: 12 B |

Key derivation uses HKDF. All cryptographic operations are deterministic, serialisation-safe, and replay-protected via nonce tracking.

```rust
// Kyber1024 key encapsulation example
use bleep_crypto::pq_crypto::{KyberKem, KyberPublicKey};

let (pk, sk) = KyberKem::keygen()?;
let (ciphertext, shared_secret) = KyberKem::encapsulate(&pk)?;
let recovered_secret = KyberKem::decapsulate(&sk, &ciphertext)?;
assert_eq!(shared_secret, recovered_secret);
```

### Dynamic Sharding

BLEEP distributes transaction processing across dynamically-managed shards:

- **AI Load Prediction** — `linfa`-based ML models forecast congestion and trigger rebalancing before bottlenecks occur
- **Cross-Shard Atomicity** — Two-phase commit (2PC) with ZK-SNARK inter-shard proofs ensures atomic cross-shard transactions
- **Shard Self-Healing** — Faulty shards are automatically isolated, transactions rerouted to healthy shards, and state rolled back and reconstructed
- **Quantum-Secure Sync** — Cross-shard state synchronisation is protected by Kyber1024 encryption and Merkle-verified

```rust
// Initialise a sharding module
let sharding = BLEEPShardingModule::new(
    16,            // initial shard count
    consensus,     // consensus reference
    p2p_node,      // P2P network handle
)?;
```

### BLEEP VM

A deterministic WebAssembly execution environment powered by [Wasmer](https://wasmer.io):

- **Strict gas metering** with per-opcode cost tables and overflow protection
- **Memory sandboxing** with configurable page limits
- **Replay protection** via per-transaction nonce tracking
- **ZK proof hints** for privacy-preserving contract execution
- **Signed transactions** with Ed25519 verification before execution

```rust
// Deploy and execute a WASM smart contract
let vm = BleepVM::new(gas_limit);
let tx = SignedTransaction {
    nonce: 1,
    gas_limit: 1_000_000,
    payload: wasm_bytecode,
    signature: sig,
    signer: pubkey,
};
let result = vm.execute_transaction(tx, &mut state)?;
println!("Gas used: {}, State root: {}", result.gas_used, hex::encode(result.state_root));
```

### Governance

BLEEP governance requires no hard forks. All protocol changes flow through an on-chain lifecycle:

```
Submit Proposal  →  AI Classification  →  ZK Voting Period
      →  Threshold Met?  →  Forkless Auto-Execution  →  Merkle-logged
```

**ZK-Private Voting** — Voters submit zero-knowledge ballots (Groth16 commitments) that are verifiable but reveal nothing about individual votes. Double-voting is cryptographically impossible via nonce-bound commitments.

**Constitutional Layer** — A set of hard-coded invariants (maximum supply, Byzantine thresholds, protocol safety rules) that governance proposals cannot override.

**Forkless Upgrades** — The `ProtocolUpgradeManager` applies state migrations atomically at a pre-agreed block height without splitting the network.

### BLEEP Connect

The cross-chain interoperability engine connects BLEEP to external blockchain networks:

```
User Request → AI Fraud Analysis → ZKP Generation → Quantum Encryption
     → Chain Adapter → RPC Execution → Merkle Confirmation
```

**Supported Networks (in development):**
Ethereum · Bitcoin · Binance Smart Chain · Solana · Polkadot · Cosmos · Avalanche · Optimism · Arbitrum · TON

### Tokenomics (BLP)

| Parameter | Value |
|---|---|
| **Maximum Supply** | 200,000,000 BLP (hard-coded, constitution-enforced) |
| **Genesis Supply** | 0 (all tokens emitted via network participation) |
| **Emission Types** | Block proposal · Participation · Healing · Cross-shard coordination |
| **Burn Types** | Transaction fees · Slashing penalties · Governance rejection |
| **Fee Distribution** | Validators 60% · Treasury 30% · Burn 10% |
| **Staking Yield** | 4–8% APY (lock-up dependent) |

Supply state is hash-committed at every epoch, enabling cryptographic proof of the circulating supply at any historical point.

---

## Testing

BLEEP maintains a comprehensive test suite across all crates:

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p bleep-consensus

# Run with output (useful for debugging)
cargo test --workspace -- --nocapture

# Run integration tests only
cargo test --workspace --test '*'

# Run property-based tests (proptest / quickcheck)
cargo test --workspace --features proptest
```

The test suite includes:
- **Unit tests** — per-module function correctness
- **Integration tests** — cross-crate interaction (phase1 through phase6 test files)
- **Safety invariant tests** — Byzantine fault tolerance and consensus invariants
- **Adversarial tests** — `bleep-core/src/adversarial_testnet.rs` simulates attack scenarios
- **Property-based tests** — randomised input validation via `proptest` and `quickcheck`

---

## Benchmarks

Performance benchmarks use [Criterion](https://github.com/bheisler/criterion.rs):

```bash
# Run all benchmarks
cargo bench --workspace

# Run a specific benchmark suite
cargo bench -p bleep-consensus

# Generate HTML benchmark report
cargo bench --workspace -- --output-format bencher | tee bench_results.txt
```

> **Note:** Throughput benchmarks validating the target transaction processing capacity are actively being developed. Results will be published in [`docs/benchmarks.md`](docs/benchmarks.md) prior to testnet launch.

---

## Roadmap

| Phase | Target | Deliverables | Status |
|---|---|---|---|
| **Phase 1** | Q4 2025 | Core protocol, consensus engines, testnet deployment | ✅ Complete |
| **Phase 2** | Q1 2026 | BLEEP VM, smart contracts, developer tooling, BLEEPat | 🔄 In Progress |
| **Phase 3** | Q4 2026 | BLEEP Connect cross-chain, live RPC adapters, liquidity pools | 🔄 In Progress |
| **Phase 4** | Q2 2027 | Production AI inference, full ONNX model deployment | 📋 Planned |
| **Phase 5** | Q4 2027 | Enterprise solutions, compliance automation, industry integrations | 📋 Planned |

Follow progress in [GitHub Issues](https://github.com/bleep-project/bleep/issues) and [GitHub Projects](https://github.com/bleep-project/bleep/projects).

[node]
p2p_port    = 7700
rpc_port    = 8545
state_dir   = "/var/lib/bleep/state"
log_level   = "info"

## Security

### Reporting Vulnerabilities

BLEEP takes security seriously. **Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues via:
- **Email:** security@bleepecosystem.com
- **PGP Key:** Available at [bleepecosystem.com/security](https://www.bleepecosystem.com/security)

We follow a 90-day responsible disclosure policy and acknowledge all valid reports within 48 hours.

### Security Architecture Principles

1. **Quantum resistance by default** — All cryptographic operations use post-quantum algorithms. Classical signatures (Ed25519, secp256k1) are supported for compatibility but not recommended for long-term asset security.
2. **AI is advisory only** — The AI decision module produces signed recommendations. It cannot execute any protocol changes without governance approval. This is enforced at the type system level.
3. **Safety over liveness** — The network halts rather than produces a conflicting state. Byzantine fault tolerance thresholds are explicitly enforced in code, not just documentation.
4. **Deterministic execution** — All consensus-critical computations (including AI inference) produce bit-identical results on every node. Non-determinism is a consensus bug.
5. **Explicit error propagation** — No panics in consensus-critical paths. All errors are typed, logged, and handled.

### Known Limitations (V1)

- Cross-chain RPC integrations (BLEEP Connect) are under active development. Live asset transfers are not yet available on mainnet.
- ONNX model files for AI inference will be bundled in Phase 4; current AI functionality operates in advisory/structural mode.
- Dark routing onion encryption is being implemented; the current P2P layer uses libp2p Noise protocol for transport security.

---

## Contributing

Contributions are welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE-OF-CONDUCT.md`](CODE-OF-CONDUCT.md) before opening a pull request.

### Development Setup

```bash
# Install development tools
cargo install cargo-audit cargo-deny cargo-watch cargo-expand

# Check formatting
cargo fmt --all -- --check

# Run linter
cargo clippy --workspace --all-targets -- -D warnings

# Run security audit
cargo audit

# Watch for changes during development
cargo watch -x "test --workspace"
```

### Pull Request Guidelines

- Every PR must pass CI (build, lint, test, security audit)
- New consensus-critical code must include safety invariant tests
- Cryptographic changes require a security review comment from a maintainer
- Breaking changes must update relevant documentation and bump the crate version

---

## Documentation

| Resource | Link |
|---|---|
| Whitepaper | [`docs/BLEEP_Whitepaper.pdf`](docs/BLEEP_Whitepaper.pdf) |
| Architecture Deep Dive | [`docs/architecture.md`](docs/architecture.md) |
| Configuration Reference | [`docs/configuration.md`](docs/configuration.md) |
| API Reference (RPC) | [`docs/rpc-api.md`](docs/rpc-api.md) |
| Smart Contract Guide | [`docs/smart-contracts.md`](docs/smart-contracts.md) |
| Validator Setup | [`docs/validator-setup.md`](docs/validator-setup.md) |
| Tokenomics Specification | [`docs/tokenomics.md`](docs/tokenomics.md) |
| Benchmarks | [`docs/benchmarks.md`](docs/benchmarks.md) |

Generated API documentation:
```bash
cargo doc --workspace --no-deps --open
```

---

## License

BLEEP is dual-licensed under **MIT** and **Apache 2.0**. You may choose either licence.

- [MIT License](LICENSE-MIT)
- [Apache 2.0 License](LICENSE-APACHE)

---

<div align="center">

Built with ❤️ in Rust by the BLEEP Ecosystem team.

[bleepecosystem.com](https://www.bleepecosystem.com) · [@BLEEPEcosystem](https://twitter.com/BLEEPEcosystem)

</div>
---

## CLI Reference

```
bleep-cli [OPTIONS] <COMMAND>

Options:
  -h, --help     Print help
  -V, --version  Print version

Environment variables:
  BLEEP_RPC        RPC endpoint     default: http://127.0.0.1:8545
  BLEEP_STATE_DIR  Local DB path    default: /tmp/bleep-state
  RUST_LOG         Log filter       default: info

Commands:
  start-node                        Start a full BLEEP node
  wallet create                     Generate SPHINCS+ keypair + encrypted wallet
  wallet balance                    Query balance from /rpc/state
  wallet import <phrase>            Import from BIP-39 mnemonic
  wallet export                     Export wallet addresses
  tx send --to <addr> --amount <n>  Sign and broadcast a transfer
  tx history                        Retrieve transaction history
  validator stake --amount <n>      Register as validator
  validator unstake                 Initiate graceful exit
  validator list                    List active validators
  validator status <id>             Validator status + slashing history
  validator submit-evidence <file>  Submit double-sign evidence
  governance propose <text>         Create a governance proposal
  governance vote <id> --yes/--no   Cast a vote
  governance list                   List all proposals
  state snapshot                    Create a RocksDB state snapshot
  state restore <path>              Restore from snapshot
  block latest                      Print the latest block
  block get <id>                    Get a block by hash or height
  block validate <hash>             Validate a block by hash
  zkp <proof>                       Verify a ZKP
  ai ask <prompt>                   Ask the AI advisory engine
  ai status                         AI engine status
  pat status                        PAT engine status
  pat list                          List asset tokens
  pat mint --to <addr> --amount <n> Mint PAT tokens (owner only)        
  pat burn --amount <n>             Burn PAT tokens                      
  pat transfer --to <addr> --amount Transfer PAT with auto burn-rate     
  pat balance <address>             Query PAT balance                    
  oracle price <asset>              Query aggregated oracle price        
  oracle submit --asset ... --price Submit oracle price update           
  economics supply                  Circulating supply, minted, burned   
  economics fee                     Current EIP-1559 base fee            
  economics epoch <n>               Epoch emissions, burns, price        
  telemetry                         Print telemetry metrics
  info                              Node version and RPC health
```

### Executor node

The `bleep-executor` binary is a separate process that participates in the Layer 4 instant intent market:

```bash
# Basic usage (ephemeral key, 0.1 BLEEP capital)
./bleep-executor

# Production usage
BLEEP_EXECUTOR_KEY=<32-byte-hex-seed>      \
BLEEP_EXECUTOR_CAPITAL_BLEEP=100000000000  \
BLEEP_EXECUTOR_CAPITAL_ETH=10000000000000000000 \
BLEEP_EXECUTOR_RISK=Medium                 \
BLEEP_RPC=http://your-node:8545            \
./bleep-executor
```



## Security Model

### Post-quantum threat model

BLEEP treats a cryptographically relevant quantum computer as a near-term engineering assumption, not a distant theoretical risk. Accordingly:

- **SPHINCS+-SHAKE-256** (NIST PQC, stateless hash-based) signs all transactions and blocks.
- **Kyber-768** (ML-KEM, NIST FIPS 203) is used for all key encapsulation.
- **AES-256-GCM** is used for symmetric encryption (128-bit post-quantum security at 256-bit key size).
- **SHA3-256 and BLAKE3** provide collision-resistant hashing.
- **Ed25519** is retained in P2P message authentication at the 128-bit classical security level and is scheduled for replacement with SPHINCS+.

### Consensus safety

- **Byzantine fault tolerance:** The system tolerates up to ⅓ of total stake being Byzantine (malicious or offline).
- **Deterministic mode selection:** No single validator can trigger a mode switch. Selection is a pure function of epoch metrics.
- **Automatic slashing:** Double-sign evidence triggers an on-chain 33% stake penalty without human intervention.
- **Irreversible finality:** Once `accumulated_voting_power > (2/3) * total_stake`, a `FinalizyCertificate` is produced. That block and its state root cannot be rolled back.

### State integrity

- **SparseMerkleTrie** ensures any modification to any account balance or nonce produces a different state root, which propagates through the block hash to the `validator_signature` and `zk_proof`. Tampered state is detectable by any node holding the state root.
- **Fiat-Shamir ZKP** binds the state root, shard state root, consensus mode, and tx count into `zk_proof`. A validator cannot produce a valid ZKP over a different set of transactions or state root.
- **Inflation invariant:** `CanonicalTokenomicsEngine` checks `total_minted ≤ MAX_SUPPLY` independently of `circulating_supply`. Concurrent burns cannot mask over-issuance.

### P2P security

- All sessions are established with Kyber-768 KEM; payload encryption is AES-256-GCM.
- An anti-replay nonce cache rejects duplicate messages within a session window.
- AI-scored peer reputation and stake-weighted selection provide Sybil resistance.
- Onion routing with 3 hops and per-hop Kyber-768 KEM prevents traffic analysis.

---

## Development Roadmap

BLEEP follows a structured, phase-based development roadmap. Phases 1–3 are complete. The four upcoming phases — AI model training, public testnet expansion, pre-sale ICO, and mainnet launch — form the path to production.

---

### Phase 1 — Foundation ✅ *Complete*

All 19 crates compile cleanly. Post-quantum cryptography active (SPHINCS+-SHAKE-256, Kyber-1024). RocksDB `StateManager` with `SparseMerkleTrie`. Full `BlockProducer` loop. Real Groth16 ZK circuits. 4-node docker-compose devnet. BLEEP Connect Layer 4 live on Ethereum Sepolia. `BleepEconomicsRuntime` (EIP-1559 fee market, oracle bridge, validator incentives). `PATRegistry` live. `bleep-executor` standalone intent market maker.

---

### Phase 2 — Testnet Alpha ✅ *Complete*

7-validator `bleep-testnet-1` genesis across 4 continents. Public DNS seeds at `seeds.testnet.bleep.network`. Public faucet (`POST /faucet/{address}`, 1,000 BLEEP per 24 hours). Block explorer (`GET /explorer`, 6 s refresh). JWT rotation, NDJSON audit export. Grafana dashboard (12 panels) + Prometheus for all 7 validators. Full CI pipeline: fmt, clippy, test, audit, build, fuzz-smoke, docker-smoke.

---

### Phase 3 — Protocol Hardening ✅ *Complete*

- ✅ **Independent security audit** — 14 findings (2 Critical, 3 High, 4 Medium, 3 Low, 2 Info); all Critical/High resolved — see `docs/SECURITY_AUDIT.md`
- ✅ **Chaos testing** — 14 scenarios, 72-hour continuous harness — see `docs/CHAOS_TESTING.md`
- ✅ **ZKP MPC ceremony** — 5-participant Powers-of-Tau on BLS12-381; transcript at `https://ceremony.bleep.network/transcript-v1.json`
- ✅ **Cross-shard stress test** — 10 shards, 1,000 concurrent cross-shard txs, 100 epochs
- ✅ **BLEEP Connect Layer 3** — Groth16 batch proof bridge live on testnet
- ✅ **Live governance** — `LiveGovernanceEngine` with typed proposals, weighted voting, veto, on-chain execution
- ✅ **Performance benchmark** — avg **10,921 TPS**, peak **13,200 TPS** across 10 shards for 1 hour
- ✅ **Token distribution model** — 6 allocation buckets, vesting schedules, 25/50/25 fee split, compile-time verified constants

**Definition of done:** Security audit fully resolved ✅ · Chaos suite 72 h ✅ · ≥10,000 TPS ✅

---

### Phase 4 — AI Model Training ⏳ *Active*

Upgrade `bleep-ai` from rule-based advisory to a trained on-chain inference engine.

- `BLEEPAIAssistant v2` — training pipeline using on-chain governance history as training data
- AI validator nodes — optional validator upgrade for AI-scored transaction prioritisation
- `AIConstraintValidator v2` — trained classification models for governance pre-flight scoring
- Determinism guarantee — all AI inference on consensus-critical paths uses fixed-seed reproducible models

**Definition of done:** AI advisory engine passes determinism test suite; governance pre-flight achieves ≥95% accuracy on labelled test set.

---

### Phase 5 — Public Testnet Expansion ⏳ *Upcoming*

Open validator onboarding to the public. Target: ≥50 validators across ≥6 continents.

- Open validator registration with public `VALIDATOR_GUIDE.md`
- Validator incentive programme from Ecosystem Fund
- `testnet.bleep.network` — multi-validator explorer, leaderboard, public dashboard
- 30-day sustained test with live validator join/leave events
- Cross-shard expansion: 10 → 20 shards as validator count permits
- Community bug bounty: up to 100,000 BLEEP for documented protocol vulnerabilities

**Definition of done:** 50+ active validators; 30 consecutive days without manual intervention.

---

### Phase 6 — Pre-Sale / ICO ⏳ *Upcoming*

Community token sale in two tranches. Deploy on-chain vesting contracts.

| Tranche | Source | Lockup |
|---|---|---|
| Strategic Pre-Sale | Strategic Reserve (5M BLEEP) | 12-month cliff + 24-month linear |
| Public ICO | Community Incentives (up to 10M BLEEP) | 6-month linear vest |

KYC/AML compliant infrastructure · Multi-sig treasury custody · `LinearVestingSchedule` contracts deployed · `GenesisAllocation` engine activated for all 6 buckets.

**Definition of done:** ICO completed; all vesting contracts deployed and verified on-chain.

---

### Phase 7 — Mainnet Launch 🔜 *Planned*

Production mainnet with post-quantum security, live economics, and cross-chain connectivity from the genesis block.

- Mainnet genesis ceremony — public, multi-party verifiable
- ≥21 validators with geographic diversity enforced by genesis rules
- BLEEP Connect L4 + L3 live on Ethereum mainnet and Solana from genesis
- Governance active from block 1
- Full tokenomics live — emission, burn, staking rewards, oracle, EIP-1559 fee market
- Block explorer at `explorer.bleep.network`
- `bleep-sdk-js` and `bleep-sdk-python` SDK releases
- NTP drift guard at node startup (warn >1 s, halt >30 s)

**Definition of done:** Genesis block produced by ≥21 independent validators; governance proposal passes on-chain within first week; cross-chain Ethereum transfer confirms within 1 second.

---

## Contributing

1. Fork the repository and create a feature branch: `git checkout -b feat/your-feature`
2. Run the full test suite: `cargo test --workspace`
3. Run the linter: `cargo clippy --workspace -- -D warnings`
4. Verify formatting: `cargo fmt --all -- --check`
5. Open a pull request against `main` with a clear description of the change and the crates affected.

Changes to `bleep-consensus`, `bleep-crypto`, or `bleep-state` undergo an extended review given their security surface area.

### Security disclosures

Do not open public issues for security vulnerabilities. Email `security@bleep.network` with a description, reproduction steps, and your proposed fix. We target 72-hour acknowledgment and a 14-day patch timeline.

---

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

---

*BLEEP Blockchain — built in Rust, secured with post-quantum cryptography, designed for the next decade of decentralised computing.*
