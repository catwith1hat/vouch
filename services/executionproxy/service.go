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

package executionproxy

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/pkg/errors"
)

// JWTSecretLength is the required byte length (256 bits) for an Engine API HS256 JWT secret.
const JWTSecretLength = 32

// EndpointConfig defines the connection and authentication settings for an execution client.
type EndpointConfig struct {
	Name      string
	URL       string
	JWTSecret []byte
}

// Service is the execution layer verification proxy service.
type Service interface {
	// ListenAddress returns the bound TCP address (host:port) of the proxy server.
	ListenAddress() string
	// Shutdown gracefully stops the proxy HTTP server.
	Shutdown(ctx context.Context) error
}

// ParseJWTSecret parses a hex-encoded 256-bit (32-byte) Engine API JWT secret.
func ParseJWTSecret(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	trimmed = bytes.TrimPrefix(trimmed, []byte("0x"))
	trimmed = bytes.TrimPrefix(trimmed, []byte("0X"))
	if len(trimmed) == 0 {
		return nil, errors.New("JWT secret is empty")
	}

	decoded := make([]byte, hex.DecodedLen(len(trimmed)))
	n, err := hex.Decode(decoded, trimmed)
	if err != nil {
		return nil, errors.Wrap(err, "invalid hex-encoded JWT secret")
	}
	decoded = decoded[:n]
	if len(decoded) != JWTSecretLength {
		return nil, errors.Errorf("JWT secret must be %d bytes, got %d", JWTSecretLength, len(decoded))
	}

	return decoded, nil
}
