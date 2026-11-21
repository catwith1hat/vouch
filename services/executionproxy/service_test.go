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

package executionproxy_test

import (
	"testing"

	"github.com/attestantio/vouch/services/executionproxy"
	"github.com/stretchr/testify/require"
)

func TestParseJWTSecret(t *testing.T) {
	validHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

	secret, err := executionproxy.ParseJWTSecret([]byte("  0x" + validHex + "\n"))
	require.NoError(t, err)
	require.Len(t, secret, executionproxy.JWTSecretLength)
	require.Equal(t, byte(0x01), secret[0])
	require.Equal(t, byte(0x20), secret[31])

	secretNoPrefix, err := executionproxy.ParseJWTSecret([]byte(validHex))
	require.NoError(t, err)
	require.Equal(t, secret, secretNoPrefix)

	_, err = executionproxy.ParseJWTSecret([]byte("   "))
	require.ErrorContains(t, err, "JWT secret is empty")

	_, err = executionproxy.ParseJWTSecret([]byte("0xzzzz"))
	require.ErrorContains(t, err, "invalid hex-encoded JWT secret")

	_, err = executionproxy.ParseJWTSecret([]byte("0x01020304"))
	require.ErrorContains(t, err, "JWT secret must be 32 bytes")
}
