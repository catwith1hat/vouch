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
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestExecutionProxyConfigParsing(t *testing.T) {
	ctx := context.Background()
	viper.Reset()
	t.Cleanup(viper.Reset)

	require.False(t, isExecutionProxyConfigured())
	require.False(t, hasBeaconNodeConfig())

	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "jwt.hex")
	secretHex := "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n"
	require.NoError(t, os.WriteFile(secretPath, []byte(secretHex), 0o600))

	yamlConfig := []byte(`
executionproxy:
  listen-address: '127.0.0.1:0'
  jwt-secret: '` + secretPath + `'
  timeout: '5s'
  primary-el:
    name: 'besu-producer'
    url: 'http://127.0.0.1:18551'
  secondary-els:
    - name: 'geth-consumer'
      url: 'http://127.0.0.1:18552'
      jwt-secret: 'direct:///0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    - 'http://127.0.0.1:18553'
`)
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(bytes.NewReader(yamlConfig)))

	require.True(t, isExecutionProxyConfigured())
	require.False(t, hasBeaconNodeConfig())

	majordomoSvc, err := initMajordomo(ctx)
	require.NoError(t, err)

	primary, err := parsePrimaryELConfig(ctx, majordomoSvc)
	require.NoError(t, err)
	require.Equal(t, "besu-producer", primary.Name)
	require.Equal(t, "http://127.0.0.1:18551", primary.URL)
	require.Empty(t, primary.JWTSecret)

	secondaries, err := parseSecondaryELConfigs(ctx, majordomoSvc)
	require.NoError(t, err)
	require.Len(t, secondaries, 2)
	require.Equal(t, "geth-consumer", secondaries[0].Name)
	require.Equal(t, "http://127.0.0.1:18552", secondaries[0].URL)
	require.Len(t, secondaries[0].JWTSecret, 32)
	require.Equal(t, "http://127.0.0.1:18553", secondaries[1].URL)

	proxySvc, err := startExecutionProxy(ctx, majordomoSvc, nullmetrics.New())
	require.NoError(t, err)
	require.NotEmpty(t, proxySvc.ListenAddress())
	require.NoError(t, proxySvc.Shutdown(ctx))
}
