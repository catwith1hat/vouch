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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	jwtHeaderEncoded = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
	jwtMaxSkewSecs   = 60
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	IssuedAt *int64 `json:"iat"`
}

// signJWT creates a compact HS256 JWT token carrying the Engine API iat claim.
func signJWT(secret []byte, now time.Time) (string, error) {
	iat := now.Unix()
	claimsJSON, err := json.Marshal(jwtClaims{IssuedAt: &iat})
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal JWT claims")
	}

	signingInput := jwtHeaderEncoded + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

// verifyAuthorizationHeader validates an HTTP Authorization header containing a Bearer HS256 JWT.
func verifyAuthorizationHeader(authHeader string, secret []byte, now time.Time) error {
	trimmed := strings.TrimSpace(authHeader)
	if len(trimmed) < 8 || !strings.EqualFold(trimmed[:7], "Bearer ") {
		return errors.New("missing Bearer token")
	}
	token := strings.TrimSpace(trimmed[7:])
	if token == "" {
		return errors.New("empty Bearer token")
	}

	return verifyJWT(token, secret, now)
}

func verifyJWT(token string, secret []byte, now time.Time) error {
	firstDot := strings.IndexByte(token, '.')
	if firstDot <= 0 {
		return errors.New("malformed JWT")
	}
	rest := token[firstDot+1:]
	secondDot := strings.IndexByte(rest, '.')
	if secondDot <= 0 || strings.IndexByte(rest[secondDot+1:], '.') != -1 {
		return errors.New("malformed JWT")
	}

	headerPart := token[:firstDot]
	claimsPart := rest[:secondDot]
	sigPart := rest[secondDot+1:]

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerPart)
	if err != nil {
		return errors.Wrap(err, "invalid JWT header encoding")
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return errors.Wrap(err, "invalid JWT header JSON")
	}
	if hdr.Alg != "HS256" {
		return errors.Errorf("unsupported JWT alg %q", hdr.Alg)
	}
	if hdr.Typ != "" && !strings.EqualFold(hdr.Typ, "JWT") {
		return errors.Errorf("unsupported JWT typ %q", hdr.Typ)
	}

	gotSig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil {
		return errors.Wrap(err, "invalid JWT signature encoding")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(token[:firstDot+1+secondDot]))
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(gotSig, expectedSig) {
		return errors.New("invalid JWT signature")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(claimsPart)
	if err != nil {
		return errors.Wrap(err, "invalid JWT claims encoding")
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return errors.Wrap(err, "invalid JWT claims JSON")
	}
	if claims.IssuedAt == nil {
		return errors.New("missing JWT iat claim")
	}

	diff := now.Unix() - *claims.IssuedAt
	if diff < -jwtMaxSkewSecs || diff > jwtMaxSkewSecs {
		return errors.New("JWT iat outside allowed +-60s window")
	}

	return nil
}
