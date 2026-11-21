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

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/attestantio/vouch/services/executionproxy"
	standardexecutionproxy "github.com/attestantio/vouch/services/executionproxy/standard"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/util"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	majordomo "github.com/wealdtech/go-majordomo"
)

const (
	defaultExecutionProxyListenAddress = "0.0.0.0:18551"
	defaultExecutionProxyTimeout       = 10 * time.Second
)

// isExecutionProxyConfigured reports whether the execution layer Pre-BAL proxy is configured.
func isExecutionProxyConfigured() bool {
	if viper.IsSet("executionproxy.primary-el") ||
		viper.IsSet("executionproxy.primary-el.url") ||
		viper.IsSet("executionproxy.listen-address") ||
		viper.IsSet("executionproxy.secondary-els") {
		return true
	}
	if viper.GetString("executionproxy.primary-el") != "" ||
		viper.GetString("executionproxy.primary-el.url") != "" ||
		viper.GetString("executionproxy.listen-address") != "" ||
		len(viper.GetStringSlice("executionproxy.secondary-els")) > 0 {
		return true
	}

	return false
}

// hasBeaconNodeConfig reports whether a consensus beacon node address is configured for validator duties.
func hasBeaconNodeConfig() bool {
	return len(util.BeaconNodeAddresses("")) > 0 || viper.GetString("beacon-node-address") != ""
}

func startExecutionProxy(
	ctx context.Context,
	majordomoSvc majordomo.Service,
	monitor metrics.Service,
) (executionproxy.Service, error) {
	defaultJWTSecret, err := loadJWTSecret(ctx, majordomoSvc, viper.GetString("executionproxy.jwt-secret"))
	if err != nil {
		return nil, errors.Wrap(err, "executionproxy: invalid jwt-secret")
	}

	var incomingJWTSecret []byte
	if incomingRef := viper.GetString("executionproxy.incoming-jwt-secret"); incomingRef != "" {
		incomingJWTSecret, err = loadJWTSecret(ctx, majordomoSvc, incomingRef)
		if err != nil {
			return nil, errors.Wrap(err, "executionproxy: invalid incoming-jwt-secret")
		}
	} else if len(defaultJWTSecret) > 0 && !viper.GetBool("executionproxy.disable-incoming-jwt-check") {
		incomingJWTSecret = defaultJWTSecret
	}

	primaryEL, err := parsePrimaryELConfig(ctx, majordomoSvc)
	if err != nil {
		return nil, err
	}

	secondaryELs, err := parseSecondaryELConfigs(ctx, majordomoSvc)
	if err != nil {
		return nil, err
	}

	listenAddress := strings.TrimSpace(viper.GetString("executionproxy.listen-address"))
	if listenAddress == "" {
		listenAddress = defaultExecutionProxyListenAddress
	}

	timeout := defaultExecutionProxyTimeout
	if viper.GetDuration("executionproxy.timeout") != 0 {
		timeout = viper.GetDuration("executionproxy.timeout")
	}

	proxySvc, err := standardexecutionproxy.New(ctx,
		standardexecutionproxy.WithLogLevel(util.LogLevel("executionproxy")),
		standardexecutionproxy.WithMonitor(monitor),
		standardexecutionproxy.WithListenAddress(listenAddress),
		standardexecutionproxy.WithPrimaryEL(primaryEL),
		standardexecutionproxy.WithSecondaryELs(secondaryELs),
		standardexecutionproxy.WithIncomingJWTSecret(incomingJWTSecret),
		standardexecutionproxy.WithDefaultJWTSecret(defaultJWTSecret),
		standardexecutionproxy.WithTimeout(timeout),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to start execution proxy")
	}

	return proxySvc, nil
}

func parsePrimaryELConfig(ctx context.Context, majordomoSvc majordomo.Service) (*executionproxy.EndpointConfig, error) {
	raw := viper.Get("executionproxy.primary-el")
	switch v := raw.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return nil, errors.New("executionproxy: no primary-el configured")
		}
		return &executionproxy.EndpointConfig{URL: strings.TrimSpace(v)}, nil
	case map[string]any, map[any]any:
		cfg, err := parseEndpointMap(ctx, majordomoSvc, toStringAnyMap(raw))
		if err != nil {
			return nil, errors.Wrap(err, "executionproxy: invalid primary-el")
		}
		return cfg, nil
	default:
		// Support environment-variable configuration such as VOUCH_EXECUTIONPROXY_PRIMARY_EL_URL.
		urlStr := strings.TrimSpace(viper.GetString("executionproxy.primary-el.url"))
		if urlStr == "" {
			return nil, errors.New("executionproxy: no primary-el configured")
		}
		jwtSecret, err := loadJWTSecret(ctx, majordomoSvc, viper.GetString("executionproxy.primary-el.jwt-secret"))
		if err != nil {
			return nil, errors.Wrap(err, "executionproxy: invalid primary-el jwt-secret")
		}
		return &executionproxy.EndpointConfig{
			Name:      strings.TrimSpace(viper.GetString("executionproxy.primary-el.name")),
			URL:       urlStr,
			JWTSecret: jwtSecret,
		}, nil
	}
}

func parseSecondaryELConfigs(ctx context.Context, majordomoSvc majordomo.Service) ([]*executionproxy.EndpointConfig, error) {
	raw := viper.Get("executionproxy.secondary-els")
	if raw == nil {
		return nil, nil
	}

	switch items := raw.(type) {
	case []string:
		res := make([]*executionproxy.EndpointConfig, 0, len(items))
		for _, item := range items {
			for _, part := range splitAddresses(item) {
				res = append(res, &executionproxy.EndpointConfig{URL: part})
			}
		}
		return res, nil
	case string:
		parts := splitAddresses(items)
		res := make([]*executionproxy.EndpointConfig, 0, len(parts))
		for _, part := range parts {
			res = append(res, &executionproxy.EndpointConfig{URL: part})
		}
		return res, nil
	case []any:
		res := make([]*executionproxy.EndpointConfig, 0, len(items))
		for i, item := range items {
			switch elem := item.(type) {
			case string:
				trimmed := strings.TrimSpace(elem)
				if trimmed == "" {
					return nil, fmt.Errorf("executionproxy: secondary-els[%d] URL is empty", i)
				}
				res = append(res, &executionproxy.EndpointConfig{URL: trimmed})
			case map[string]any, map[any]any:
				cfg, err := parseEndpointMap(ctx, majordomoSvc, toStringAnyMap(item))
				if err != nil {
					return nil, errors.Wrapf(err, "executionproxy: invalid secondary-els[%d]", i)
				}
				res = append(res, cfg)
			default:
				return nil, fmt.Errorf("executionproxy: unsupported type %T for secondary-els[%d]", item, i)
			}
		}
		return res, nil
	default:
		return nil, fmt.Errorf("executionproxy: unsupported secondary-els configuration type %T", raw)
	}
}

func parseEndpointMap(
	ctx context.Context,
	majordomoSvc majordomo.Service,
	m map[string]any,
) (*executionproxy.EndpointConfig, error) {
	var urlStr, nameStr, jwtRef string
	for k, val := range m {
		switch {
		case strings.EqualFold(k, "url") || strings.EqualFold(k, "address"):
			urlStr = strings.TrimSpace(fmt.Sprint(val))
		case strings.EqualFold(k, "name"):
			nameStr = strings.TrimSpace(fmt.Sprint(val))
		case strings.EqualFold(k, "jwt-secret") || strings.EqualFold(k, "jwt_secret"):
			jwtRef = strings.TrimSpace(fmt.Sprint(val))
		}
	}
	if urlStr == "" {
		return nil, errors.New("missing url")
	}
	jwtSecret, err := loadJWTSecret(ctx, majordomoSvc, jwtRef)
	if err != nil {
		return nil, errors.Wrap(err, "invalid jwt-secret")
	}

	return &executionproxy.EndpointConfig{
		Name:      nameStr,
		URL:       urlStr,
		JWTSecret: jwtSecret,
	}, nil
}

func toStringAnyMap(raw any) map[string]any {
	switch typed := raw.(type) {
	case map[string]any:
		return typed
	case map[any]any:
		res := make(map[string]any, len(typed))
		for k, v := range typed {
			res[fmt.Sprint(k)] = v
		}
		return res
	default:
		return nil
	}
}

func splitAddresses(input string) []string {
	fields := strings.FieldsFunc(input, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	res := make([]string, 0, len(fields))
	for _, f := range fields {
		trimmed := strings.TrimSpace(f)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}

	return res
}

func loadJWTSecret(ctx context.Context, majordomoSvc majordomo.Service, ref string) ([]byte, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, nil
	}

	if strings.Contains(ref, "://") {
		if majordomoSvc == nil {
			return nil, errors.New("majordomo service unavailable to fetch JWT secret URL")
		}
		raw, err := majordomoSvc.Fetch(ctx, ref)
		if err != nil {
			return nil, errors.Wrap(err, "failed to fetch JWT secret from majordomo")
		}
		return executionproxy.ParseJWTSecret(raw)
	}

	// Support either a filesystem path (resolved against base-dir) or a direct 32-byte hex string.
	resolved := resolvePath(ref)
	if fileData, err := os.ReadFile(resolved); err == nil {
		return executionproxy.ParseJWTSecret(fileData)
	}
	if parsed, hexErr := executionproxy.ParseJWTSecret([]byte(ref)); hexErr == nil {
		return parsed, nil
	}

	raw, err := os.ReadFile(resolved)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read JWT secret file %s", resolved)
	}

	return executionproxy.ParseJWTSecret(raw)
}
