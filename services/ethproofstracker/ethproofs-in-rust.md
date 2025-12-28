# Ethproofs.org Integration in Rust

This document details the integration of [ethproofs.org](https://ethproofs.org) into the Lighthouse-based execution layer client, as found in the `lighthouse` subdirectory (branch `ethproofs/zkattester-demo`).

## Overview

The `zkvm_execution_layer` crate provides the core logic for fetching, managing, and verifying zero-knowledge proofs (zk-proofs) of Ethereum block execution. This integration allows the beacon node to cryptographically verify that the execution payload of a block has been proven correct by a zkVM before accepting it.

### Architecture

The system is designed with a **Dynamic Prover Loading** architecture. Instead of hardcoding verification keys (VKs) and prover configurations, the client fetches the active set of provers and their keys from the Ethproofs API at startup.

Key components:

1.  **Prover Registry (`EthproofsProverRegistry`):** Maps internal `proof_id`s to Ethproofs `cluster_id`s and `zkvm_slug`s.
2.  **Verifier Store (`VerifierStore`):** A registry of available verifier implementations (e.g., SP1, OpenVM, ZisK), keyed by `zkvm_slug`.
3.  **Dynamic VK Store:** Stores the verification keys fetched from the API, keyed by `proof_id`.
4.  **Proof Validator:** coordinates the verification process using the above components.

## Implementation Details

### 1. Dynamic Loading (`active_provers_loader.rs`)

At startup, `initialize_ethproofs_provers()` calls `load_active_provers()`, which:
*   Queries `https://ethproofs.org/api/v0/verification-keys/active`.
*   Parses the JSON response containing active clusters, their `zkvm_slug` (e.g., "sp1-hypercube"), and base64-encoded verification keys.
*   Sorts provers by `cluster_id` and assigns them a sequential `proof_id` (u8).
*   Decodes the verification keys.
*   Populates the global `PROVER_REGISTRY` and `DYNAMIC_VK_STORE`.

### 2. Proof Verification Flow (`ethproofs_demo.rs`)

The validation logic is encapsulated in `validate_proof(proof: &ExecutionProof)`:

1.  **Fallback Check:** If `proof_id` is 0, it's treated as a "fallback" proof (often used for testing or when proofs are disabled) and accepted immediately.
2.  **Registry Lookup:** The `proof_id` is looked up in the `PROVER_REGISTRY` to retrieve the corresponding `zkvm_slug` and `cluster_id`.
3.  **VK Lookup:** The Verification Key is retrieved from `DYNAMIC_VK_STORE` using the `proof_id`.
4.  **Verifier Lookup:** The `zkvm_slug` is used to look up the correct verifier function in `VERIFIER_STORE`.
5.  **Cryptographic Verification:** The verifier function is called with the proof data and the verification key.

### 3. Supported zkVMs (`verifiers/`)

The `verifiers` module contains implementations for various zkVMs, wrapping their respective Rust crates. Each verifier implements the `ProofVerifier` trait.

*   **SP1 Hypercube (`verifiers/sp1_hypercube.rs`):**
    *   Uses `sp1_verifier` crate.
    *   Verifies using `SP1CompressedVerifierRaw::verify`.
    *   Wrapped in `panic_safe::safe_verify` to prevent FFI/library panics from crashing the node.

*   **OpenVM (`verifiers/openvm.rs`):**
    *   Uses `verify_stark` crate.
    *   Deserializes keys using `bitcode`.
    *   Verifies using `verify_vm_stark_proof`.

*   **Pico (`verifiers/pico.rs`):**
    *   Uses `pico_prism_vm` crate.
    *   Handles KoalaBear field arithmetic and recursion proofs.
    *   Deserializes proofs and keys using `bincode`.

*   **ZisK (`verifiers/zisk.rs`):**
    *   Uses `proofman_verifier` crate.

*   **Others:** `airbender`, `fallback`.

### 4. API Interaction

*   **Fetching Proofs:** `fetch_proof_from_ethproofs` polls `https://ethproofs.org/api/v0/proofs?block={hash}&clusters={cluster_id}` with exponential backoff.
*   **Downloading Binaries:** `download_proof_binary` fetches the raw proof data from `https://ethproofs.org/api/v0/proofs/download/{proof_id}`.
*   **Authentication:** Supports `ETHPROOFS_API_KEY` environment variable for authenticated requests.

## Code Structure

*   `zkvm_execution_layer/src/`
    *   `ethproofs_demo.rs`: Main entry point, validation logic, and API client.
    *   `active_provers_loader.rs`: Logic for fetching and parsing active provers configuration.
    *   `ethproofs_prover_registry.rs`: Data structures for mapping proof IDs to clusters.
    *   `verifiers/`: Directory containing specific zkVM verifier implementations.
        *   `mod.rs`: `VerifierStore` implementation and registry.
        *   `sp1_hypercube.rs`: SP1 verifier adapter.
        *   `openvm.rs`: OpenVM verifier adapter.
        *   ...

## Usage

This integration is designed to run within the Lighthouse beacon node. When enabled, the beacon node will:
1.  Initialize the prover registry at startup.
2.  When processing a block, determine if a proof is required.
3.  Fetch the proof from Ethproofs.org (if not already available).
4.  Verify the proof using the dynamically loaded keys and the appropriate verifier.
