// Copyright © 2020 - 2025 Attestant Limited.
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

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

// poll is the periodic job that checks for new ethproofs.
func (s *Service) poll(ctx context.Context) {
	currentEpoch := s.chainTime.CurrentEpoch()

	// Only poll if we've advanced to a new epoch.
	if currentEpoch <= s.lastPolledEpoch {
		return
	}

	s.log.Trace().
		Uint64("current_epoch", uint64(currentEpoch)).
		Uint64("last_polled_epoch", uint64(s.lastPolledEpoch)).
		Msg("Polling ethproofs")

	// Poll backwards from current epoch to lastPolledEpoch.
	// Limit to last 5 epochs to avoid overwhelming the API.
	epochsToCheck := int64(5)
	if currentEpoch-s.lastPolledEpoch < phase0.Epoch(epochsToCheck) {
		epochsToCheck = int64(currentEpoch - s.lastPolledEpoch)
	}

	for i := int64(0); i < epochsToCheck && currentEpoch-phase0.Epoch(i) > 0; i++ {
		epoch := currentEpoch - phase0.Epoch(i)
		s.checkEpochProof(ctx, epoch)
	}

	s.lastPolledEpoch = currentEpoch
	s.lastPollTime = time.Now()
}

// checkEpochProof checks if a specific epoch has a proof on ethproofs.org.
func (s *Service) checkEpochProof(ctx context.Context, epoch phase0.Epoch) {
	// Get first slot of epoch.
	firstSlot := s.chainTime.FirstSlotOfEpoch(epoch)

	// Get block root for that slot.
	blockRoot, err := s.getBlockRootForSlot(ctx, firstSlot)
	if err != nil {
		s.log.Warn().
			Err(err).
			Uint64("epoch", uint64(epoch)).
			Uint64("slot", uint64(firstSlot)).
			Msg("Failed to get block root for epoch")
		return
	}

	// Query ethproofs API.
	proven, err := s.queryEthproofs(ctx, blockRoot)
	if err != nil {
		s.log.Debug().
			Err(err).
			Uint64("epoch", uint64(epoch)).
			Str("root", fmt.Sprintf("%#x", blockRoot)).
			Msg("Ethproofs query failed")
		return
	}

	// Update cache.
	s.provenEpochsMu.Lock()
	if proven {
		s.provenEpochs[epoch] = blockRoot
		s.log.Trace().
			Uint64("epoch", uint64(epoch)).
			Str("root", fmt.Sprintf("%#x", blockRoot)).
			Msg("Epoch proven by ethproofs")
	} else {
		// Mark as checked but not proven by removing from cache.
		delete(s.provenEpochs, epoch)
	}
	s.provenEpochsMu.Unlock()

	monitorEthproofsQuery(proven)
}

// getBlockRootForSlot retrieves the block root for a specific slot from the beacon chain.
func (s *Service) getBlockRootForSlot(ctx context.Context, slot phase0.Slot) (phase0.Root, error) {
	blockID := fmt.Sprintf("%d", slot)

	rootResponse, err := s.beaconBlockRootProvider.BeaconBlockRoot(ctx, &api.BeaconBlockRootOpts{
		Block: blockID,
	})
	if err != nil {
		return phase0.Root{}, errors.Wrap(err, "failed to obtain beacon block root")
	}

	if rootResponse == nil || rootResponse.Data == nil {
		return phase0.Root{}, errors.New("beacon block root response is nil")
	}

	return *rootResponse.Data, nil
}

// queryEthproofs queries the ethproofs.org API and cryptographically verifies the Groth16 proof.
func (s *Service) queryEthproofs(ctx context.Context, blockRoot phase0.Root) (bool, error) {
	started := time.Now()

	// Step 1: Query API to get proof metadata
	proofID, zkvmType, err := s.queryProofMetadata(ctx, blockRoot)
	if err != nil {
		monitorEthproofsAPILatency(started)
		return false, err
	}
	if proofID == "" {
		// No proof found (expected case)
		monitorEthproofsAPILatency(started)
		return false, nil
	}

	// Step 2: Download the actual proof binary
	proofData, err := s.downloadProof(ctx, proofID)
	if err != nil {
		monitorEthproofsAPILatency(started)
		return false, errors.Wrap(err, "failed to download proof")
	}

	monitorEthproofsAPILatency(started)

	// Step 3: Cryptographically verify the proof using Rust FFI
	result, err := VerifyEthproof(zkvmType, proofData, blockRoot)
	if err != nil {
		return false, errors.Wrap(err, "failed to call verifier")
	}

	switch result {
	case VerifySuccess:
		s.log.Debug().
			Str("proof_id", proofID).
			Str("block_root", fmt.Sprintf("%#x", blockRoot)).
			Uint8("zkvm", uint8(zkvmType)).
			Msg("Proof verified successfully via FFI")
		return true, nil

	case VerifyFailed:
		s.log.Warn().
			Str("proof_id", proofID).
			Str("block_root", fmt.Sprintf("%#x", blockRoot)).
			Uint8("zkvm", uint8(zkvmType)).
			Msg("Proof verification failed")
		return false, nil

	case VerifyError:
		return false, fmt.Errorf("verifier returned error for proof %s", proofID)

	default:
		return false, fmt.Errorf("unknown verifier result: %d", result)
	}
}

// queryProofMetadata queries the API for proof metadata and returns the proof ID and zkVM type if it exists.
func (s *Service) queryProofMetadata(ctx context.Context, blockRoot phase0.Root) (string, ZkVMType, error) {
	reqCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Format URL: /api/v0/proofs?block=0x...
	url := fmt.Sprintf("%s/proofs?block=%#x", s.ethproofsBaseURL, blockRoot)

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return "", ZkVMSP1, errors.Wrap(err, "failed to create HTTP request")
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", ZkVMSP1, errors.Wrap(err, "failed to query ethproofs API")
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var result struct {
			Proofs []struct {
				ID     string `json:"id"`
				ZkvmID string `json:"zkvm_id"`
			} `json:"proofs"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return "", ZkVMSP1, errors.Wrap(err, "failed to decode ethproofs response")
		}

		// Return the first proof ID if available
		if len(result.Proofs) > 0 {
			zkvm := parseZkvmType(result.Proofs[0].ZkvmID)
			return result.Proofs[0].ID, zkvm, nil
		}
		return "", ZkVMSP1, nil

	case http.StatusNotFound:
		return "", ZkVMSP1, nil

	default:
		return "", ZkVMSP1, fmt.Errorf("ethproofs API returned status %d", resp.StatusCode)
	}
}

// parseZkvmType converts a zkvm_id string to a ZkVMType
func parseZkvmType(zkvmID string) ZkVMType {
	switch zkvmID {
	case "sp1", "SP1":
		return ZkVMSP1
	case "zkm", "ZKM", "ziren", "Ziren":
		return ZkVMZKM
	case "pico", "Pico":
		return ZkVMPico
	default:
		// Default to SP1 (most common)
		return ZkVMSP1
	}
}

// downloadProof downloads the actual proof binary from the API.
func (s *Service) downloadProof(ctx context.Context, proofID string) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, s.timeout*3) // Longer timeout for download
	defer cancel()

	// Format URL: /api/v0/proofs/download/{id}
	url := fmt.Sprintf("%s/proofs/download/%s", s.ethproofsBaseURL, proofID)

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create HTTP request")
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to download proof")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Read the entire binary
	proofBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read proof binary")
	}

	s.log.Trace().
		Str("proof_id", proofID).
		Int("size_bytes", len(proofBytes)).
		Msg("Downloaded proof binary")

	return proofBytes, nil
}

// cleanCache removes old epochs from the cache.
func (s *Service) cleanCache(ctx context.Context) {
	currentEpoch := s.chainTime.CurrentEpoch()

	// Keep last cacheSize epochs.
	threshold := phase0.Epoch(0)
	if currentEpoch > phase0.Epoch(s.cacheSize) {
		threshold = currentEpoch - phase0.Epoch(s.cacheSize)
	}

	s.provenEpochsMu.Lock()
	defer s.provenEpochsMu.Unlock()

	for epoch := range s.provenEpochs {
		if epoch < threshold {
			delete(s.provenEpochs, epoch)
			s.log.Trace().
				Uint64("epoch", uint64(epoch)).
				Msg("Removed epoch from cache")
		}
	}

	monitorEthproofsCacheSize(len(s.provenEpochs))
}
