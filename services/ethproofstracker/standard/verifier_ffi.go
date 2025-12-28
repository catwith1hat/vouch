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

package standard

// #cgo LDFLAGS: -L${SRCDIR}/../lib -lethproofs_verifier
// #cgo linux LDFLAGS: -Wl,-rpath,${SRCDIR}/../lib
// #cgo darwin LDFLAGS: -Wl,-rpath,${SRCDIR}/../lib
// #include "../verifier/verifier.h"
// #include <stdlib.h>
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// ZkVMType represents the type of zkVM that generated the proof
type ZkVMType uint8

const (
	// ZkVMSP1 represents Succinct's SP1 zkVM
	ZkVMSP1 ZkVMType = 0
	// ZkVMZKM represents ZKM's Ziren zkVM
	ZkVMZKM ZkVMType = 1
	// ZkVMPico represents Brevis's Pico zkVM
	ZkVMPico ZkVMType = 2
)

// VerifyResult represents the result of proof verification
type VerifyResult uint8

const (
	// VerifyFailed indicates the proof verification failed
	VerifyFailed VerifyResult = 0
	// VerifySuccess indicates the proof was successfully verified
	VerifySuccess VerifyResult = 1
	// VerifyError indicates an error occurred during verification
	VerifyError VerifyResult = 2
)

// VerifyEthproof verifies a ZK proof using the Rust FFI verifier
func VerifyEthproof(zkvm ZkVMType, proofData []byte, vkeyHash string, vkData []byte, blockRoot phase0.Root) (VerifyResult, error) {
	if len(proofData) == 0 {
		return VerifyError, fmt.Errorf("proof data is empty")
	}

	// Prepare VK data pointer
	var vkPtr *C.uint8_t
	var vkLen C.size_t
	if len(vkData) > 0 {
		vkPtr = (*C.uint8_t)(unsafe.Pointer(&vkData[0]))
		vkLen = C.size_t(len(vkData))
	}

	// Prepare VKey hash C string
	cVkeyHash := C.CString(vkeyHash)
	defer C.free(unsafe.Pointer(cVkeyHash))

	// Call the Rust FFI function
	result := C.verify_ethproof(
		C.uint8_t(zkvm),
		(*C.uint8_t)(unsafe.Pointer(&proofData[0])),
		C.size_t(len(proofData)),
		cVkeyHash,
		vkPtr,
		vkLen,
		(*C.uint8_t)(unsafe.Pointer(&blockRoot[0])),
	)

	return VerifyResult(result), nil
}

// GetVerifierVersion returns the version string of the Rust verifier library
func GetVerifierVersion() string {
	cstr := C.get_verifier_version()
	return C.GoString(cstr)
}
