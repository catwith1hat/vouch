/* Copyright © 2025 Attestant Limited.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ETHPROOFS_VERIFIER_H
#define ETHPROOFS_VERIFIER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ZkVM type identifiers */
#define ZKVM_SP1   0
#define ZKVM_ZKM   1
#define ZKVM_PICO  2

/* Verification result codes */
#define VERIFY_FAILED  0
#define VERIFY_SUCCESS 1
#define VERIFY_ERROR   2

/**
 * Verify a ZK proof from ethproofs.org
 *
 * @param zkvm_type     The zkVM type (ZKVM_SP1, ZKVM_ZKM, or ZKVM_PICO)
 * @param proof_ptr     Pointer to the proof binary data
 * @param proof_len     Length of the proof binary in bytes
 * @param block_root_ptr Pointer to the expected block root (must be 32 bytes)
 * @return VERIFY_SUCCESS (1) if verified, VERIFY_FAILED (0) if invalid, VERIFY_ERROR (2) if error
 */
uint8_t verify_ethproof(
    uint8_t zkvm_type,
    const uint8_t* proof_ptr,
    size_t proof_len,
    const uint8_t* block_root_ptr
);

/**
 * Get the version string of the verifier library
 *
 * @return Null-terminated C string with version info (do not free)
 */
const char* get_verifier_version(void);

#ifdef __cplusplus
}
#endif

#endif /* ETHPROOFS_VERIFIER_H */
