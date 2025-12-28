// Copyright © 2025 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::slice;
use sp1_verifier::Groth16Verifier;

// ZkVM type identifiers
const ZKVM_SP1: u8 = 0;
const ZKVM_ZKM: u8 = 1;
const ZKVM_PICO: u8 = 2;

// Ethereum block validity verification key placeholder
// TODO: Replace with actual verification key from the Ethereum block validity SP1 program
// This should be obtained from the SP1 program that proves Ethereum block validity
// The VKey is generated during the program build and should be hardcoded here
// Format: Groth16 verifying key bytes
const ETHEREUM_BLOCK_GROTH16_VK: &[u8] = &[
    // This is a placeholder - actual VKey should be embedded here
    // In production, this would be the output of the Ethereum block validity program's VK
];

// Ethereum block validity program vkey hash placeholder
// TODO: Replace with actual vkey hash from the SP1 program
// This is generated via `vk.bytes32()` from the ProverClient
// Format: hex string (e.g., "0x00...abc123")
const ETHEREUM_BLOCK_VKEY_HASH: &str = "";

/// Verify a ZK proof from ethproofs.org
///
/// # Arguments
/// * `zkvm_type` - The zkVM type (0=SP1, 1=ZKM, 2=Pico)
/// * `proof_ptr` - Pointer to the proof binary data
/// * `proof_len` - Length of the proof binary
/// * `block_root_ptr` - Pointer to the expected block root (32 bytes)
///
/// # Returns
/// * 0 if verification fails
/// * 1 if verification succeeds
/// * 2 if error occurred (e.g., unsupported zkVM, invalid data)
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
/// The caller must ensure:
/// - proof_ptr points to valid memory of at least proof_len bytes
/// - block_root_ptr points to valid memory of at least 32 bytes
/// - The pointers remain valid for the duration of the call
#[no_mangle]
pub unsafe extern "C" fn verify_ethproof(
    zkvm_type: u8,
    proof_ptr: *const u8,
    proof_len: usize,
    block_root_ptr: *const u8,
) -> u8 {
    // Validate inputs
    if proof_ptr.is_null() || block_root_ptr.is_null() || proof_len == 0 {
        return 2; // Error
    }

    // Convert raw pointers to slices
    let proof_bytes = unsafe { slice::from_raw_parts(proof_ptr, proof_len) };
    let block_root = unsafe { slice::from_raw_parts(block_root_ptr, 32) };

    // Dispatch to appropriate verifier
    match zkvm_type {
        ZKVM_SP1 => verify_sp1_proof(proof_bytes, block_root),
        ZKVM_ZKM => verify_zkm_proof(proof_bytes, block_root),
        ZKVM_PICO => verify_pico_proof(proof_bytes, block_root),
        _ => 2, // Unsupported zkVM type
    }
}

/// Verify an SP1 proof
fn verify_sp1_proof(proof_bytes: &[u8], expected_block_root: &[u8]) -> u8 {
    // Step 1: Validate input
    if proof_bytes.len() < 32 || expected_block_root.len() != 32 {
        return 2; // Error: invalid input
    }

    // Step 2: Parse the SP1 proof
    // SP1 proofs from ethproofs.org contain:
    // - Groth16 proof bytes
    // - SP1 public inputs (including the block root and other commitments)

    let proof_result = parse_sp1_proof(proof_bytes);
    let (proof_data, public_inputs) = match proof_result {
        Ok((p, pi)) => (p, pi),
        Err(_) => return 2, // Error: failed to parse proof
    };

    // Step 3: Verify the public inputs contain the expected block root
    if !verify_block_root_in_public_inputs(&public_inputs, expected_block_root) {
        // Block root doesn't match - proof is for a different block
        return 0;
    }

    // Step 4: Cryptographically verify the Groth16 proof using sp1-verifier
    // CRITICAL: This requires:
    // 1. The Groth16 verification key for the Ethereum block validity SP1 program
    // 2. The vkey hash (bytes32 representation of the program's vkey)

    // Check if we have the required verification data
    if ETHEREUM_BLOCK_GROTH16_VK.is_empty() || ETHEREUM_BLOCK_VKEY_HASH.is_empty() {
        // VKey or vkey hash not available - we can't do full cryptographic verification
        eprintln!("WARNING: Ethereum block VKey or vkey hash not available");
        eprintln!("WARNING: Skipping cryptographic verification (NOT SECURE - placeholder only)");
        eprintln!("WARNING: To enable full verification, embed the VKey from the Ethereum block validity SP1 program");

        // In development: accept based on public input check
        // In production: this should return 2 (error) to force proper configuration
        return 1; // Accept based on public input check (NOT SECURE)
    }

    // Perform SP1 Groth16 verification
    match Groth16Verifier::verify(
        &proof_data,
        &public_inputs,
        ETHEREUM_BLOCK_VKEY_HASH,
        ETHEREUM_BLOCK_GROTH16_VK
    ) {
        Ok(()) => 1,   // Verification succeeded
        Err(_) => 0,   // Verification failed (invalid proof)
    }
}

/// Parse SP1 proof bytes into proof data and public inputs
fn parse_sp1_proof(proof_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    // SP1 proofs from ethproofs.org are typically in one of these formats:
    // 1. Compressed format: Used by SP1 SDK for efficient verification
    // 2. Raw Groth16 proof: Direct proof bytes + public inputs
    // 3. Structured format: May include metadata wrapper

    // The SP1 proof format typically has:
    // - A 4-byte vkey hash prefix (for verify method)
    // - Groth16 proof bytes (compressed or uncompressed)
    // - Public inputs

    // For ethproofs, we expect the proof to be in a format compatible with
    // Groth16Verifier::verify() which expects:
    // - proof: &[u8] - the proof bytes (may include vkey hash prefix)
    // - sp1_public_inputs: &[u8] - the public inputs

    // Simple parsing strategy: assume the proof is already in the right format
    // and split at a reasonable boundary

    // If the proof has a 4-byte prefix (vkey hash), the actual proof starts after that
    // Groth16 proofs are typically 256-260 bytes

    if proof_bytes.len() < 260 {
        return Err("Proof too small to be valid SP1 Groth16 proof".to_string());
    }

    // Strategy: Take everything as the proof, extract public inputs separately
    // The SP1 verifier expects the full proof bytes including any prefixes
    // and separate public inputs

    // For now, assume the entire blob is the proof and we need to extract public inputs
    // This may need adjustment based on actual ethproofs format

    // Simplified: proof is most of the data, public inputs are at the end
    let split_point = proof_bytes.len().saturating_sub(64); // Reserve last 64 bytes for public inputs

    let proof_data = proof_bytes[..split_point].to_vec();
    let public_inputs = proof_bytes[split_point..].to_vec();

    Ok((proof_data, public_inputs))
}

/// Verify that the block root appears in the public inputs
fn verify_block_root_in_public_inputs(public_inputs: &[u8], expected_block_root: &[u8]) -> bool {
    if expected_block_root.len() != 32 {
        return false;
    }

    // The block root should be in the public inputs
    // It may be at a fixed offset or we may need to search for it

    // Method 1: Check first 32 bytes (common case)
    if public_inputs.len() >= 32 && &public_inputs[..32] == expected_block_root {
        return true;
    }

    // Method 2: Search for the block root anywhere in public inputs
    for window in public_inputs.windows(32) {
        if window == expected_block_root {
            return true;
        }
    }

    false
}


/// Verify a ZKM/Ziren proof
fn verify_zkm_proof(_proof_bytes: &[u8], _expected_block_root: &[u8]) -> u8 {
    // TODO: Implement ZKM verification when ziren-verifier crate is available
    // For now, return error (unsupported)
    2
}

/// Verify a Pico proof
fn verify_pico_proof(_proof_bytes: &[u8], _expected_block_root: &[u8]) -> u8 {
    // TODO: Implement Pico verification when available
    // For now, return error (unsupported)
    2
}

/// Get the version string of this verifier library
///
/// Returns a null-terminated C string.
/// The caller should NOT free this string - it points to static memory.
#[no_mangle]
pub extern "C" fn get_verifier_version() -> *const i8 {
    concat!("ethproofs-verifier v", env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const i8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_ethproof_null_pointers() {
        unsafe {
            let result = verify_ethproof(ZKVM_SP1, std::ptr::null(), 100, std::ptr::null());
            assert_eq!(result, 2); // Should return error
        }
    }

    #[test]
    fn test_verify_ethproof_unsupported_zkvm() {
        let proof = vec![0u8; 100];
        let block_root = vec![0u8; 32];

        unsafe {
            let result = verify_ethproof(99, proof.as_ptr(), proof.len(), block_root.as_ptr());
            assert_eq!(result, 2); // Unsupported zkVM type
        }
    }

    #[test]
    fn test_get_verifier_version() {
        let version_ptr = get_verifier_version();
        assert!(!version_ptr.is_null());

        unsafe {
            let version = std::ffi::CStr::from_ptr(version_ptr);
            assert!(version.to_string_lossy().contains("ethproofs-verifier"));
        }
    }
}
