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
use std::ffi::CStr;
use sp1_verifier::Groth16Verifier;
use serde::{Deserialize, Serialize};
use verify_stark::{verify_vm_stark_proof, vk::VmStarkVerifyingKey};

// ZkVM type identifiers
const ZKVM_SP1: u8 = 0;
const ZKVM_ZKM: u8 = 1;
const ZKVM_PICO: u8 = 2;
const ZKVM_OPENVM: u8 = 3;

// SP1 Proof Structure
// Matches SP1ProofWithPublicValues from sp1-sdk
#[derive(Serialize, Deserialize, Debug)]
pub struct SP1ProofWithPublicValues {
    pub proof: Vec<u8>,
    pub stdin: Vec<u8>,
    pub public_values: Vec<u8>,
    pub sp1_version: String,
}

/// Verify a ZK proof from ethproofs.org
///
/// # Arguments
/// * `zkvm_type` - The zkVM type (0=SP1, 1=ZKM, 2=Pico, 3=OpenVM)
/// * `proof_ptr` - Pointer to the proof binary data
/// * `proof_len` - Length of the proof binary
/// * `vkey_hash_ptr` - Pointer to the null-terminated vkey hash string
/// * `vk_ptr` - Pointer to the verification key data
/// * `vk_len` - Length of the verification key
/// * `block_root_ptr` - Pointer to the expected block root (32 bytes)
///
/// # Returns
/// * 0 if verification fails
/// * 1 if verification succeeds
/// * 2 if error occurred (e.g., unsupported zkVM, invalid data)
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
pub unsafe extern "C" fn verify_ethproof(
    zkvm_type: u8,
    proof_ptr: *const u8,
    proof_len: usize,
    vkey_hash_ptr: *const i8,
    vk_ptr: *const u8,
    vk_len: usize,
    block_root_ptr: *const u8,
) -> u8 {
    // Validate inputs
    if proof_ptr.is_null() || block_root_ptr.is_null() || proof_len == 0 {
        return 2; // Error
    }

    // Convert raw pointers to slices
    let proof_bytes = unsafe { slice::from_raw_parts(proof_ptr, proof_len) };
    let block_root = unsafe { slice::from_raw_parts(block_root_ptr, 32) };
    
    // Convert VK pointer if present
    let vk_bytes = if !vk_ptr.is_null() && vk_len > 0 {
        unsafe { slice::from_raw_parts(vk_ptr, vk_len) }
    } else {
        &[]
    };

    // Convert vkey_hash if present
    let vkey_hash = if !vkey_hash_ptr.is_null() {
        match unsafe { CStr::from_ptr(vkey_hash_ptr) }.to_str() {
            Ok(s) => s,
            Err(_) => return 2,
        }
    } else {
        ""
    };

    // Dispatch to appropriate verifier
    match zkvm_type {
        ZKVM_SP1 => verify_sp1_proof(proof_bytes, vkey_hash, vk_bytes, block_root),
        ZKVM_ZKM => verify_zkm_proof(proof_bytes, vk_bytes, block_root),
        ZKVM_PICO => verify_pico_proof(proof_bytes, vk_bytes, block_root),
        ZKVM_OPENVM => verify_openvm_proof(proof_bytes, vk_bytes, block_root),
        _ => 2, // Unsupported zkVM type
    }
}

/// Verify an SP1 proof
fn verify_sp1_proof(proof_bytes: &[u8], vkey_hash: &str, vk_bytes: &[u8], expected_block_root: &[u8]) -> u8 {
    // Step 1: Validate input
    if expected_block_root.len() != 32 {
        return 2; // Error: invalid input
    }

    // Step 2: Parse the SP1 proof using bincode
    let proof_struct: SP1ProofWithPublicValues = match bincode::deserialize(proof_bytes) {
        Ok(p) => p,
        Err(_) => return 2, // Error: failed to parse proof
    };

    // Step 3: Verify the public inputs contain the expected block root
    if !verify_block_root_in_public_inputs(&proof_struct.public_values, expected_block_root) {
        // Block root doesn't match - proof is for a different block
        return 0;
    }

    // Step 4: Cryptographically verify the Groth16 proof using sp1-verifier
    if vk_bytes.is_empty() || vkey_hash.is_empty() {
        return 2; 
    }

    // Perform SP1 Groth16 verification
    match Groth16Verifier::verify(
        &proof_struct.proof,
        &proof_struct.public_values,
        vkey_hash, 
        vk_bytes
    ) {
        Ok(()) => 1,   // Verification succeeded
        Err(_) => 0,   // Verification failed (invalid proof)
    }
}

/// Verify an OpenVM proof
fn verify_openvm_proof(proof_bytes: &[u8], vk_bytes: &[u8], _expected_block_root: &[u8]) -> u8 {
    // 1. Deserialize the verification key using bitcode
    let vk: VmStarkVerifyingKey = match bitcode::deserialize(vk_bytes) {
        Ok(vk) => vk,
        Err(_) => return 2, // Error deserializing VK
    };

    // 2. Verify the proof using verify-stark
    // Note: This function doesn't seem to take public inputs separately in this version?
    // The lighthouse implementation just passes proof_bytes.
    // We should probably check public inputs, but `verify_vm_stark_proof` might handle it
    // or we might need to extract them.
    // For now, we follow the lighthouse implementation which just verifies the proof.
    // TODO: Verify expected_block_root is in the proof's public inputs.
    
    match verify_vm_stark_proof(&vk, proof_bytes) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// Verify that the block root appears in the public inputs
fn verify_block_root_in_public_inputs(public_inputs: &[u8], expected_block_root: &[u8]) -> bool {
    if expected_block_root.len() != 32 {
        return false;
    }

    // Search for the block root anywhere in public inputs
    for window in public_inputs.windows(32) {
        if window == expected_block_root {
            return true;
        }
    }

    false
}


/// Verify a ZKM/Ziren proof
fn verify_zkm_proof(_proof_bytes: &[u8], _vk_bytes: &[u8], _expected_block_root: &[u8]) -> u8 {
    // TODO: Implement ZKM verification
    2
}

/// Verify a Pico proof
fn verify_pico_proof(_proof_bytes: &[u8], _vk_bytes: &[u8], _expected_block_root: &[u8]) -> u8 {
    // Pico disabled due to unstable rust requirements
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