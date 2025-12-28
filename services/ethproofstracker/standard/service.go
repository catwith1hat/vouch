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
	"net/http"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service tracks ethproofs-verified epochs.
type Service struct {
	log                     zerolog.Logger
	monitor                 metrics.Service
	chainTime               chaintime.Service
	beaconBlockRootProvider eth2client.BeaconBlockRootProvider
	httpClient              *http.Client
	ethproofsBaseURL        string
	timeout                 time.Duration
	cacheSize               int

	// Cache of proven epochs: map[epoch]blockRoot.
	provenEpochsMu sync.RWMutex
	provenEpochs   map[phase0.Epoch]phase0.Root

	// Track polling state.
	lastPolledEpoch phase0.Epoch
	lastPollTime    time.Time
}

// New creates a new ethproofs tracker service.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log := zerologger.With().Str("service", "ethproofstracker").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.New("failed to register metrics")
	}

	s := &Service{
		log:                     log,
		monitor:                 parameters.monitor,
		chainTime:               parameters.chainTime,
		beaconBlockRootProvider: parameters.beaconBlockRootProvider,
		httpClient: &http.Client{
			Timeout: parameters.timeout,
		},
		ethproofsBaseURL: parameters.baseURL,
		timeout:          parameters.timeout,
		cacheSize:        parameters.cacheSize,
		provenEpochs:     make(map[phase0.Epoch]phase0.Root),
		lastPolledEpoch:  0,
	}

	// Schedule periodic polling job.
	if err := parameters.scheduler.SchedulePeriodicJob(ctx,
		"Ethproofs tracker",
		"Poll ethproofs.org",
		func(_ context.Context) (time.Time, error) {
			return time.Now().Add(parameters.pollInterval), nil
		},
		s.poll,
	); err != nil {
		return nil, errors.Wrap(err, "failed to schedule periodic polling")
	}

	// Schedule periodic cache cleanup.
	if err := parameters.scheduler.SchedulePeriodicJob(ctx,
		"Ethproofs tracker",
		"Clean ethproofs cache",
		func(_ context.Context) (time.Time, error) {
			// Clean approximately every 32 epochs (~3.4 hours).
			return time.Now().Add(32 * 384 * time.Second), nil
		},
		s.cleanCache,
	); err != nil {
		return nil, errors.Wrap(err, "failed to schedule cache cleanup")
	}

	log.Info().
		Str("base_url", s.ethproofsBaseURL).
		Dur("poll_interval", parameters.pollInterval).
		Int("cache_size", s.cacheSize).
		Msg("Ethproofs tracker started")

	return s, nil
}

// IsEpochProven checks if a specific epoch's first slot block has been proven by ethproofs.
func (s *Service) IsEpochProven(ctx context.Context, epoch phase0.Epoch) bool {
	s.provenEpochsMu.RLock()
	defer s.provenEpochsMu.RUnlock()

	_, proven := s.provenEpochs[epoch]
	return proven
}
