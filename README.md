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

---

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

## Faucet & Wallet

BLEEP includes a combined wallet + faucet system with:

- Wallet creation and import
- AI-based management features
- Multi-chain integration
- Cross-chain distribution via **BLEEP Connect**
- WASM contract support

---

## Development Roadmap

- [x] Node deployment and configuration
- [x] BLP token model finalized
- [x] AI module architecture defined
- [ ] PAT module implementation
- [ ] Faucet + Wallet integration
- [ ] Cross-chain support with BLEEP Connect
- [ ] AI/Quantum/ZK upgrades to BLEEP VM
- [ ] Super App ecosystem front-end

---

## 🔧 Testnet Status

BLEEP is currently in internal testnet mode with multiple validator nodes under simulation.  
A public testnet (with explorer, faucet, and developer tools) will launch in **Q4 2025**.

---

## 💖 Support BLEEP

BLEEP is self-funded and fully open-source. Your support accelerates core development, ecosystem growth, and infrastructure audits.

### Donate Crypto

| Asset | Address | Link |
|-------|---------|------|
| **ETH / USDT (ERC-20)** | `0x4c3ceb507f7b2f976b31caed45ceeefab5ee5bd2` | [View on Etherscan](https://etherscan.io/address/0x4c3ceb507f7b2f976b31caed45ceeefab5ee5bd2) |
| **BTC** | `16mMB2di5BMCjGTEzf49mPvF5QSkxz2NVX` | [View on Blockchain.com](https://www.blockchain.com/btc/address/16mMB2di5BMCjGTEzf49mPvF5QSkxz2NVX) |
| **TRC-20 USDT** | `TDmE78aQnLHdaVNRnXFKykXpLfb6j4UgDj` | [View on Tronscan](https://tronscan.org/#/address/TDmE78aQnLHdaVNRnXFKykXpLfb6j4UgDj) |

---

## Contributing

We welcome developers, researchers, and testers.

1. Fork the repository
2. Create your branch: `git checkout -b feature/my-feature`
3. Commit changes: `git commit -am 'Add feature'`
4. Push and create a PR

Please follow our [Code of Conduct](./.github/CODE_OF_CONDUCT.md).

---

## 🌐 Community

- **Website**: [https://bleepecosystem.com](https://bleepecosystem.com)
- **GitHub**: [https://github.com/BleepEcosystem](https://github.com/BleepEcosystem)
- **X (Twitter)**: [@bleepecosystem](https://x.com/bleepecosystem)
- **Telegram**: [Join Chat](https://t.me/bleepecosystem)
- **Discord**: https://discord.gg/KSrHuYFcpD

---

## License

This repository is licensed under the Apache License 2.0. See the [LICENSE](./LICENSE) file for details.

Some subcomponents are under different licenses:

- Smart contracts (`/smart-contracts`) – GNU GPLv3  
- SDKs (`/sdk`) – MIT License  
- Virtual Machine (`/vm`) – Business Source License 1.1  
- Documentation (`/docs`) – Creative Commons Attribution 4.0 (CC-BY-4.0)
