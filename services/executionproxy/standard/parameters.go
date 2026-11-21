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
	"fmt"
	"net"
	"net/url"
	"slices"
	"time"

	"github.com/attestantio/vouch/services/executionproxy"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

const (
	defaultTimeout      = 10 * time.Second
	defaultMaxBodyBytes = 64 * 1024 * 1024
)

type parameters struct {
	monitor           metrics.Service
	listenAddress     string
	primaryEL         *executionproxy.EndpointConfig
	secondaryELs      []*executionproxy.EndpointConfig
	incomingJWTSecret []byte
	defaultJWTSecret  []byte
	timeout           time.Duration
	maxBodyBytes      int64
	logLevel          zerolog.Level
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(p *parameters)
}

type parameterFunc func(*parameters)

func (f parameterFunc) apply(p *parameters) {
	f(p)
}

// WithLogLevel sets the log level for the module.
func WithLogLevel(logLevel zerolog.Level) Parameter {
	return parameterFunc(func(p *parameters) { p.logLevel = logLevel })
}

// WithMonitor sets the monitor for the module.
func WithMonitor(monitor metrics.Service) Parameter {
	return parameterFunc(func(p *parameters) { p.monitor = monitor })
}

// WithListenAddress sets the HTTP listen address for incoming consensus client Engine API requests.
func WithListenAddress(listenAddress string) Parameter {
	return parameterFunc(func(p *parameters) { p.listenAddress = listenAddress })
}

// WithPrimaryEL sets the primary stateful execution client (Pre-BAL producer).
func WithPrimaryEL(primaryEL *executionproxy.EndpointConfig) Parameter {
	return parameterFunc(func(p *parameters) { p.primaryEL = primaryEL })
}

// WithSecondaryELs sets the secondary stateless execution clients (Pre-BAL consumers).
func WithSecondaryELs(secondaryELs []*executionproxy.EndpointConfig) Parameter {
	return parameterFunc(func(p *parameters) { p.secondaryELs = secondaryELs })
}

// WithIncomingJWTSecret sets the optional 32-byte HS256 secret used to validate incoming consensus client requests.
func WithIncomingJWTSecret(secret []byte) Parameter {
	return parameterFunc(func(p *parameters) { p.incomingJWTSecret = slices.Clone(secret) })
}

// WithDefaultJWTSecret sets the default 32-byte HS256 secret used to sign outbound requests to execution clients.
func WithDefaultJWTSecret(secret []byte) Parameter {
	return parameterFunc(func(p *parameters) { p.defaultJWTSecret = slices.Clone(secret) })
}

// WithTimeout sets the per-request timeout for execution client RPC calls.
func WithTimeout(timeout time.Duration) Parameter {
	return parameterFunc(func(p *parameters) { p.timeout = timeout })
}

// WithMaxBodyBytes sets the maximum decompressed JSON-RPC body size accepted or read by the proxy.
func WithMaxBodyBytes(maxBodyBytes int64) Parameter {
	return parameterFunc(func(p *parameters) { p.maxBodyBytes = maxBodyBytes })
}

func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := &parameters{
		logLevel:     zerolog.GlobalLevel(),
		timeout:      defaultTimeout,
		maxBodyBytes: defaultMaxBodyBytes,
	}
	for _, p := range params {
		if p != nil {
			p.apply(parameters)
		}
	}
	if err := parameters.validate(); err != nil {
		return nil, err
	}

	return parameters, nil
}

func (p *parameters) validate() error {
	if p.monitor == nil {
		return errors.New("no monitor specified")
	}
	if p.listenAddress == "" {
		return errors.New("no listen address specified")
	}
	if _, _, err := net.SplitHostPort(p.listenAddress); err != nil {
		return errors.Wrap(err, "listen address malformed")
	}
	if p.primaryEL == nil {
		return errors.New("no primary execution client specified")
	}
	normalizedPrimary, err := normalizeEndpoint(p.primaryEL, "primary")
	if err != nil {
		return errors.Wrap(err, "invalid primary execution client")
	}
	p.primaryEL = normalizedPrimary

	normalizedSecondaries := make([]*executionproxy.EndpointConfig, 0, len(p.secondaryELs))
	for i, sec := range p.secondaryELs {
		if sec == nil {
			return fmt.Errorf("secondary execution client at index %d is nil", i)
		}
		normalized, err := normalizeEndpoint(sec, fmt.Sprintf("secondary-%d", i))
		if err != nil {
			return errors.Wrapf(err, "invalid secondary execution client at index %d", i)
		}
		normalizedSecondaries = append(normalizedSecondaries, normalized)
	}
	p.secondaryELs = normalizedSecondaries

	if len(p.incomingJWTSecret) != 0 && len(p.incomingJWTSecret) != executionproxy.JWTSecretLength {
		return fmt.Errorf("incoming JWT secret must be %d bytes", executionproxy.JWTSecretLength)
	}
	if len(p.defaultJWTSecret) != 0 && len(p.defaultJWTSecret) != executionproxy.JWTSecretLength {
		return fmt.Errorf("default JWT secret must be %d bytes", executionproxy.JWTSecretLength)
	}
	if p.timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if p.maxBodyBytes <= 0 {
		return errors.New("max body bytes must be positive")
	}

	return nil
}

func normalizeEndpoint(cfg *executionproxy.EndpointConfig, fallbackName string) (*executionproxy.EndpointConfig, error) {
	if cfg.URL == "" {
		return nil, errors.New("no URL specified")
	}
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, errors.Wrap(err, "malformed URL")
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("URL must use http or https scheme with a valid host")
	}
	if len(cfg.JWTSecret) != 0 && len(cfg.JWTSecret) != executionproxy.JWTSecretLength {
		return nil, fmt.Errorf("JWT secret must be %d bytes", executionproxy.JWTSecretLength)
	}

	name := cfg.Name
	if name == "" {
		name = parsed.Host
		if name == "" {
			name = fallbackName
		}
	}

	return &executionproxy.EndpointConfig{
		Name:      name,
		URL:       cfg.URL,
		JWTSecret: slices.Clone(cfg.JWTSecret),
	}, nil
}
