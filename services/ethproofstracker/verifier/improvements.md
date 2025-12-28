# Improvements for Ethproofs Verifier Service

## 1. Context and Problem Statement

The current implementation of the `ethproofs-verifier` crate (in `services/ethproofstracker/verifier`) is designed as a **Static Verifier**. It attempts to verify zero-knowledge proofs by hardcoding the Verification Keys (VKs) directly into the binary constant `ETHEREUM_BLOCK_GROTH16_VK`.

**The Core Issue:**
The user correctly identified that "vkey things are missing for the sp1 verifier." Specifically:
1.  `ETHEREUM_BLOCK_GROTH16_VK` is empty/placeholder.
2.  `ETHEREUM_BLOCK_VKEY_HASH` is empty.
3.  The code insecurely bypasses cryptographic verification (`return 1`) when these keys are missing.

## 2. The Architectural Mismatch

By analyzing the `lighthouse` checkout (specifically `ethproofs/zkattester-demo`), we observed that the ecosystem uses a **Dynamic Prover Loading** architecture. The Ethproofs API provides the active Verification Keys at runtime because:
*   Circuits are upgraded frequently.
*   Different provers (SP1, ZKM, Pico) have different keys.
*   The set of active provers changes dynamically.

Hardcoding a single SP1 VKey into the `ethproofs-verifier` library will cause the verifier to fail or become obsolete as soon as the circuit is upgraded.

## 3. Proposed Improvements

### A. Dynamic Verification Key Injection (FFI Update)

Instead of hardcoding the VKey, we must modify the FFI signature to accept the VKey from the caller (the Vouch Go service). The Vouch service will be responsible for fetching the VK from the Ethproofs API (as documented in `ethproofs-in-rust.md`) and passing it down.

**Current Signature:**
```rust
pub unsafe extern "C" fn verify_ethproof(
    zkvm_type: u8,
    proof_ptr: *const u8,
    proof_len: usize,
    block_root_ptr: *const u8,
) -> u8
```

**Proposed Signature:**
```rust
pub unsafe extern "C" fn verify_ethproof(
    zkvm_type: u8,
    proof_ptr: *const u8,
    proof_len: usize,
    vk_ptr: *const u8,      // <--- NEW: Pointer to Verification Key
    vk_len: usize,          // <--- NEW: Length of Verification Key
    block_root_ptr: *const u8,
) -> u8
```

### B. Robust SP1 Proof Parsing

The current parsing logic is naive and brittle:
```rust
// Naive split at last 64 bytes
let split_point = proof_bytes.len().saturating_sub(64);
```

**Improvement:**
Use `bincode` or `serde` to deserialize the proof structure properly. The SP1 proof format (often `SP1ProofWithPublicValues`) is a structured object. We should define the minimal expected struct in Rust and deserialize it to safely extract `public_values` and the underlying `proof`.

```rust
#[derive(Deserialize)]
struct SP1ProofWithPublicValues {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
    // ... other fields
}

fn parse_sp1_proof(data: &[u8]) -> Result<SP1ProofWithPublicValues, ...> {
    bincode::deserialize(data)
}
```

### C. Implementing the Verification Logic

With the VKey injected dynamically, we can remove the insecure bypass and implement the actual check.

**Revised `verify_sp1_proof` logic:**
1.  **Deserialize VK:** Parse `vk_ptr` into the format expected by `sp1-verifier` (likely a `Groth16VerifyingKey` struct or raw bytes depending on the verifier version).
2.  **Deserialize Proof:** Parse `proof_ptr` into `proof` and `public_inputs`.
3.  **Semantic Check:** Verify `public_inputs` contains `expected_block_root`.
4.  **Cryptographic Check:**
    ```rust
    Groth16Verifier::verify(
        &proof,
        &public_inputs,
        &vk_hash, // Derived from VK or passed separately
        &vk       // The injected VK
    )
    ```

### D. Support for Multiple zkVMs

The `lighthouse` implementation supports OpenVM, Pico, and ZisK. The current `ethproofs-verifier` has stubs for `ZKVM_ZKM` and `ZKVM_PICO`.

*   **Action:** Copy the `verifiers/` module structure from the `lighthouse` checkout into this crate.
*   **Action:** Update `Cargo.toml` to include dependencies for these other verifiers (or use conditional compilation features to keep binary size low).

## 4. Immediate Action Plan (Fixing "Missing VKey")

If the goal is specifically to fix the **SP1** verification in the short term without a full architectural rewrite:

1.  **Update `Cargo.toml`:** Add `bincode` and `serde`.
2.  **Define Structs:** Add the `SP1ProofWithPublicValues` struct definition.
3.  **Update FFI:** Change `verify_ethproof` to accept `vk_ptr` / `vk_len`.
4.  **Implementation:**
    ```rust
    fn verify_sp1_proof(proof_bytes: &[u8], vk_bytes: &[u8], expected_root: &[u8]) -> u8 {
        // 1. Parse Proof
        let proof_struct: SP1ProofWithPublicValues = bincode::deserialize(proof_bytes).map_err(...)?;

        // 2. Check Public Inputs
        if !proof_struct.public_values.contains(expected_root) { return 0; }

        // 3. Verify
        // Note: sp1-verifier might expect the VKey in a specific format (e.g., BN254 points).
        // We assume vk_bytes is already in that format from the API.
        sp1_verifier::Groth16Verifier::verify(
            &proof_struct.proof,
            &proof_struct.public_values,
            &vk_bytes
        ).map(|_| 1).unwrap_or(0)
    }
    ```
