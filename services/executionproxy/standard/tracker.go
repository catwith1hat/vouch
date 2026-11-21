// Copyright © 2026 Attestant Limited.
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
	"encoding/json"
	"strings"
	"sync"
)

const defaultTrackedBlocksCap = 4096

type rejectedBlock struct {
	status          string
	latestValidHash json.RawMessage
	validationError string
}

// blockTracker remembers blocks that failed secondary Pre-BAL verification so
// subsequent engine_forkchoiceUpdated or descendant engine_newPayload calls cannot
// promote an unverified or invalid block on the primary execution client.
type blockTracker struct {
	rejected        map[string]rejectedBlock
	rejectedOrder   []string
	unverified      map[string]struct{}
	unverifiedOrder []string
	maxEntries      int
	mutex           sync.RWMutex
}

func newBlockTracker(maxEntries int) *blockTracker {
	if maxEntries <= 0 {
		maxEntries = defaultTrackedBlocksCap
	}

	return &blockTracker{
		rejected:   make(map[string]rejectedBlock),
		unverified: make(map[string]struct{}),
		maxEntries: maxEntries,
	}
}

func normalizeHash(hash string) string {
	return strings.ToLower(strings.TrimSpace(hash))
}

func isZeroOrEmptyHash(hash string) bool {
	h := normalizeHash(hash)
	if h == "" {
		return true
	}
	h = strings.TrimPrefix(h, "0x")
	if h == "" {
		return true
	}
	for i := range len(h) {
		if h[i] != '0' {
			return false
		}
	}

	return true
}

func (t *blockTracker) markRejected(blockHash string, entry rejectedBlock) {
	key := normalizeHash(blockHash)
	if isZeroOrEmptyHash(key) {
		return
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	delete(t.unverified, key)
	if _, exists := t.rejected[key]; !exists {
		if len(t.rejectedOrder) >= t.maxEntries {
			evict := t.rejectedOrder[0]
			t.rejectedOrder = t.rejectedOrder[1:]
			delete(t.rejected, evict)
		}
		t.rejectedOrder = append(t.rejectedOrder, key)
	}
	t.rejected[key] = entry
}

func (t *blockTracker) markUnverified(blockHash string) {
	key := normalizeHash(blockHash)
	if isZeroOrEmptyHash(key) {
		return
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	if _, isRejected := t.rejected[key]; isRejected {
		return
	}
	if _, exists := t.unverified[key]; !exists {
		if len(t.unverifiedOrder) >= t.maxEntries {
			evict := t.unverifiedOrder[0]
			t.unverifiedOrder = t.unverifiedOrder[1:]
			delete(t.unverified, evict)
		}
		t.unverifiedOrder = append(t.unverifiedOrder, key)
		t.unverified[key] = struct{}{}
	}
}

func (t *blockTracker) markVerified(blockHash string) {
	key := normalizeHash(blockHash)
	if isZeroOrEmptyHash(key) {
		return
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	delete(t.unverified, key)
	delete(t.rejected, key)
}

func (t *blockTracker) lookupRejected(blockHash string) (rejectedBlock, bool) {
	key := normalizeHash(blockHash)
	if isZeroOrEmptyHash(key) {
		return rejectedBlock{}, false
	}

	t.mutex.RLock()
	defer t.mutex.RUnlock()

	entry, exists := t.rejected[key]
	return entry, exists
}

func (t *blockTracker) isUnverified(blockHash string) bool {
	key := normalizeHash(blockHash)
	if isZeroOrEmptyHash(key) {
		return false
	}

	t.mutex.RLock()
	defer t.mutex.RUnlock()

	_, exists := t.unverified[key]
	return exists
}
