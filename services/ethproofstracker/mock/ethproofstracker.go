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

package mock

import (
	"context"
	"sync"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/ethproofstracker"
)

// EthproofsTracker is a mock ethproofs tracker.
type EthproofsTracker struct {
	provenEpochsMu sync.RWMutex
	provenEpochs   map[phase0.Epoch]phase0.Root
}

// New creates a new mock ethproofs tracker.
func New() ethproofstracker.Service {
	return &EthproofsTracker{
		provenEpochs: make(map[phase0.Epoch]phase0.Root),
	}
}

// IsEpochProven checks if a specific epoch has been proven.
func (m *EthproofsTracker) IsEpochProven(_ context.Context, epoch phase0.Epoch) bool {
	m.provenEpochsMu.RLock()
	defer m.provenEpochsMu.RUnlock()

	_, exists := m.provenEpochs[epoch]
	return exists
}

// SetProvenEpoch sets an epoch as proven (test helper).
func (m *EthproofsTracker) SetProvenEpoch(epoch phase0.Epoch, root phase0.Root) {
	m.provenEpochsMu.Lock()
	defer m.provenEpochsMu.Unlock()

	m.provenEpochs[epoch] = root
}
