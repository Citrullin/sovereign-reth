# Sovereign Reth: The Manifold Architecture

The **Consensus Database** of the Sovereignty‑Stack Manifold. 
Sovereign Reth is a pure‑stateless, witness‑executed sovereign Ethereum node utilizing Celestia-style DA, cross-manifold BGP routing, and Dual-Path Proof of Trust (DPoT).

**We are building a Manifold.** 

Forget the standard "Web3" and "L2 rollup sequencer" narratives. We are not interested in token selling. Our focus is purely on the technology: building a sovereign, robust, and mathematically sound infrastructure based on hardware-attested trust, stateless execution, and physical-layer routing.

---

## The Paradigm Shift

| Feature | Legacy IP + Ethereum | Our Sovereign Manifold |
|---------|----------------------|----------------------------|
| **Network Layer** | Public IP / DNS | **Raw Fiber + `did:peer:4` Cryptokey Routing (WireGuard)** |
| **Identity** | None (Added at App Layer) | **Unified cryptographic root (Zero-KMS)** |
| **State Footprint** | Bloated global MPT | **Stateless (WitnessDatabase) + IPFS Cluster** |
| **Hardware cost** | High-end server class | **$10 Embedded ARMv7 Board + secondhand SSD** |
| **Cross-Chain** | Insecure Multisig Bridges | **BGP-style Cross-Manifold Precompiles (`0xff`)** |

---

## Architecture & Vision

### 1. The Physical Layer & Network Peering (The Fiber/WireGuard Bridge)
We eliminate external DNS, ICANN registration, and public IP routing for node-to-node consensus entirely.
* **Cryptokey Peering:** Over physical fiber, connections are managed by a local WireGuard interface (`wg0`).
* **Zero-KMS (Single-Key Derivation):** On boot, the node derives all keys from a single seed:
  * *Layer 1/2:* Curve25519 key for WireGuard transport encryption.
  * *Layer 3/4:* Ed25519 key representing the `did:peer:4` offline document.
  * *Layer 5+:* `secp256k1` key for signing EVM blocks.
* **Zero-Config Handshake:** Operators simply trade `did:peer:4` URIs. The node automatically extracts the WireGuard public key, configures the secure tunnel, and whitelists the peer's EVM key.

### 2. Implicit State & The Execution Block
We abandon local state for validators entirely. 
The blockchain does not hold the state index. The state is represented strictly by a 32-byte State Root hash ($S_n$). The transition to $S_{n+1}$ is proven by applying a tiny State Diff ($\Delta$).
Peer nodes **do not run the EVM** to verify blocks. They apply the state diff directly to their local memory map and assert the new State Root is mathematically correct.

### 3. Gateway vs. Validator Split & The Witness Mempool
We split the network to protect user wallets from generating massive cryptographic witnesses:
* **Stateful RPC Gateway (`--node-type replica`):** Stores the flat state (backed by TiKV/CockroachDB), receives standard TXs, dry-runs them, generates the cryptographic `ExecutionWitness`, and gossips the `Transaction + Witness Bundle` to validators.
* **Stateless Validator Node (`--node-type validator`):** Executes transactions in-memory via `WitnessDatabase`. Checks memory limits (fits easily inside 2GB SGX EPC).
* **Witness-Enabled FCFS Mempool:** Transactions are First-Come-First-Serve. The validator mempool explicitly intercepts intents, verifies the attached witness mathematically against the *current* State Root, and instantly rejects stale/invalid txs.
* **Parallel EVM (Block-STM):** Mandatory EIP-2930 storage access keys allow the stateless validator to run parallel execution across non-conflicting threads natively with zero DB I/O latency.

### 4. Data Availability: Celestia Tricks (NMTs + DAS)
State availability is completely offloaded to a local IPFS/IPLD Cluster.
* **State as Git (IPLD DAGs):** State updates are saved as content-addressed IPLD blocks on IPFS. Deduplication ensures only changed state diffs consume physical disk space.
* **Namespaced Merkle Trees (NMTs):** Blocks are formatted as NMTs. Applications are assigned unique namespaces (e.g., `NS_02` for Nextcloud). Validators only download and verify state diffs for the namespaces they care about.
* **Data Availability Sampling (DAS):** Low-power edge devices act as DAS light nodes, randomly sampling 16 IPLD chunks (2D Reed-Solomon Erasure Coded) to verify block availability before signing consensus.

### 5. BGP-Style Cross-Manifold Routing
We treat separate manifolds like Autonomous Systems (AS) in BGP internet routing, lowered into native EVM executions via Argot's `solcore` compiler.
* **The Cross-Manifold Precompile (`0xff`):** Cross-chain reads compile to a `STATICCALL` to precompile `0xff`. The precompile recovers validator signatures, verifies the proof against the target manifold's IPFS-cached validator list, and returns the value in milliseconds.
* **Overlapping Validator Gossip Queue:** For writes, overlapping validators act as BGP routers, capturing the signed intent and routing it across the `wg0` boundary into the destination manifold's Gateway mempool.

### 6. ZKP Federated Identity (Authentik + SIWE)
Replacing heavy DAO governance with a federated identity stack:
* **Off-Chain Directory:** Authentik manages user roles/groups off-chain.
* **Root Commitments:** A relay compiles the active user directory into a sparse Merkle tree and posts the 32-byte root hash on-chain.
* **Zero-Knowledge Proofs (ZKPs):** Users log in via SIWE, generate a local ZKP (e.g., groth16 or SP1) proving their credential exists under the root commitment, and execute transactions without storing personal data on-chain.

### 7. The Dual-Path Admission Layer & Slashing Engine
The entry ticket to the block-building validator pool bypasses Proof of Stake.
* **Path A: TEE Automatic Registration (Zero-Trust):** Embeds an ephemeral public key in hardware quotes (SGX/TDX/SEV-SNP). Includes explicit DEBUG rejections to prevent exploits.
* **Path B: Vanilla Social Registration (Proof of Reputation):** Operator signs a delegation payload using an offline `did:peer:4` master key. Peers resolve it locally against a TinyMeritRank threshold.
* **The Slashing Engine:** An $O(1)$ memory operation evicts bad actors from the `AllowedSequencers` registry with dynamic TinyMeritRank decay (e.g., Equivocation = Full eviction).

---

## Crate Topology

```text
sovereign-reth/
├── Cargo.toml                 # Includes SP1/groth16 ZKP deps & paradigmxyz/stateless
└── crates/
    ├── node/                  # Custom Reth Node Builder & CLI (--node-type replica|validator)
    ├── consensus/             # The Hybrid Consensus & Validation Engine
    │   ├── src/
    │   │   ├── stateless.rs   # Implements WitnessDatabase validation & Block-STM integration
    │   │   ├── nmt.rs         # Celestia-style Namespaced Merkle Tree hasher
    │   │   ├── registry.rs    # Unified TEE and did:peer:4 validator directory
    │   │   ├── bgp.rs         # BGP IPFS Validator Directory syncing
    │   │   ├── precompile.rs  # Cross-Manifold `0xff` Precompile (AWM/IBC style)
    │   │   └── slashing.rs    # ReputationSlash handler, TinyMeritRank decay & auto-eviction
    ├── attestation/           # Hardware quote generation utility
    │   ├── src/
    │   │   ├── sgx.rs         # /dev/sgx_enclave via Gramine
    │   │   └── mock.rs        # Mock provider for Vanilla nodes
    ├── identity/              # did:peer:4, PoR Resolver, and ZKP Auth
    │   ├── src/
    │   │   ├── delegation.rs  # Session-key authorization checks
    │   │   ├── merit.rs       # Interfaces local TiKV/MDBX TinyMeritRank
    │   │   └── zkp_auth.rs    # SIWE/Authentik ZKP verification logic
    └── network/               # Physical Layer & Peering
        ├── src/
            ├── wireguard.rs   # wg0 interface management
            ├── handshake.rs   # Single-Key derivation & Zero-Config peering
            └── bgp_gossip.rs  # Overlapping validator cross-manifold routing queues
```

---

## Getting Started

This repository is designed so you can pull it, build it, and it just works.

### Prerequisites

You must have Rust (with `clang` and `libclang-dev`) and Node.js installed.

```bash
sudo apt-get update && sudo apt-get install -y clang libclang-dev nodejs
```

### 1. Compile Smart Contracts
The custom paymaster contract must be compiled to generate the runtime bytecode:

```bash
cd contracts
npm install
node compile.js
cd ..
```

### 2. Generate Genesis Configuration
Generate the `genesis.json` configuration file, pre-allocating state for the EntryPoint and the compiled paymaster contract:

```bash
node build_genesis.js
```

### 3. Launching the Network

**Important Build Constraints:**
Due to an Internal Compiler Error (ICE) in the default `1.97.0` Rust compiler when compiling `bindgen` with MIR optimizations, and the high memory requirements of compiling RocksDB (C++), you **MUST** run the build commands with specific flags. We restrict parallel jobs (`-j 1`) to prevent OOM crashes on embedded hardware.

```bash
export RUSTC_BOOTSTRAP=1
export RUSTFLAGS="-Z mir-opt-level=0"
export CXX=clang++
export CC=clang
export NUM_JOBS=1

cargo build --release -j 1
```

#### A. Run a Stateful RPC Gateway
The Gateway acts as the RPC provider for wallets. It stores the flat state, dry-runs transactions, and generates cryptographic execution witnesses.

```bash
./target/release/sovereign-reth node \
  --node-type replica \
  --chain genesis.json \
  --datadir db \
  --http --http.api all --http.corsdomain "*"
```

#### B. Run a Stateless Validator (Vanilla/ARMv7)
The pure in-memory executor. No state database is required. It verifies witnesses, applies state diffs, and pushes data to IPFS.

```bash
./target/release/sovereign-reth node \
  --node-type validator \
  --chain genesis.json \
  --tee none \
  --did-peer4 "did:peer:4zQmd..." \
  --delegation-proof ./delegation.sig \
  --merit-threshold 0.05
```

#### C. Run a Stateless Validator (SGX Enclave via Gramine)
Because the validator is stateless, the entire execution environment easily fits inside a 2GB SGX EPC cache without paging.

```bash
# Build and sign the Gramine manifest
cd gramine
./build.sh

# Launch the node securely inside the enclave
gramine-sgx sovereign-reth node \
  --node-type validator \
  --chain ../genesis.json \
  --tee sgx \
  --approved-mrenclave 0x...
```
