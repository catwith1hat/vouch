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
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/scheduler"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel                zerolog.Level
	monitor                 metrics.Service
	chainTime               chaintime.Service
	beaconBlockRootProvider eth2client.BeaconBlockRootProvider
	scheduler               scheduler.Service
	baseURL                 string
	pollInterval            time.Duration
	timeout                 time.Duration
	cacheSize               int
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(p *parameters)
}

type parameterFunc func(*parameters)

func (f parameterFunc) apply(p *parameters) {
	f(p)
}

// WithLogLevel sets the log level for the service.
func WithLogLevel(logLevel zerolog.Level) Parameter {
	return parameterFunc(func(p *parameters) {
		p.logLevel = logLevel
	})
}

// WithMonitor sets the monitor for the service.
func WithMonitor(monitor metrics.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithChainTime sets the chain time service.
func WithChainTime(service chaintime.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.chainTime = service
	})
}

// WithBeaconBlockRootProvider sets the beacon block root provider.
func WithBeaconBlockRootProvider(provider eth2client.BeaconBlockRootProvider) Parameter {
	return parameterFunc(func(p *parameters) {
		p.beaconBlockRootProvider = provider
	})
}

// WithScheduler sets the scheduler for periodic jobs.
func WithScheduler(scheduler scheduler.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.scheduler = scheduler
	})
}

// WithBaseURL sets the ethproofs API base URL.
func WithBaseURL(baseURL string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.baseURL = baseURL
	})
}

// WithPollInterval sets the polling interval.
func WithPollInterval(interval time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.pollInterval = interval
	})
}

// WithTimeout sets the HTTP request timeout.
func WithTimeout(timeout time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.timeout = timeout
	})
}

// WithCacheSize sets the number of epochs to cache.
func WithCacheSize(size int) Parameter {
	return parameterFunc(func(p *parameters) {
		p.cacheSize = size
	})
}

// parseAndCheckParameters parses and checks parameters to ensure they are valid.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel:     zerolog.GlobalLevel(),
		baseURL:      "https://ethproofs.org/api/v0",
		pollInterval: 12 * time.Second,
		timeout:      2 * time.Second,
		cacheSize:    100,
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.monitor == nil {
		return nil, errors.New("no monitor specified")
	}
	if parameters.chainTime == nil {
		return nil, errors.New("no chain time service specified")
	}
	if parameters.beaconBlockRootProvider == nil {
		return nil, errors.New("no beacon block root provider specified")
	}
	if parameters.scheduler == nil {
		return nil, errors.New("no scheduler specified")
	}
	if parameters.baseURL == "" {
		return nil, errors.New("no base URL specified")
	}
	if parameters.pollInterval == 0 {
		return nil, errors.New("no poll interval specified")
	}
	if parameters.timeout == 0 {
		return nil, errors.New("no timeout specified")
	}
	if parameters.cacheSize <= 0 {
		return nil, errors.New("cache size must be positive")
	}

	return &parameters, nil
}
