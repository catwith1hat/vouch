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

package standard_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attestantio/vouch/services/executionproxy"
	"github.com/attestantio/vouch/services/executionproxy/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func makeSecret(fill byte) []byte {
	secret := make([]byte, executionproxy.JWTSecretLength)
	for i := range secret {
		secret[i] = fill
	}

	return secret
}

func mintTestJWT(t *testing.T, secret []byte, iat int64) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"HS256"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iat":%d}`, iat)))
	signingInput := header + "." + claims
	mac := hmac.New(sha256.New, secret)
	_, err := mac.Write([]byte(signingInput))
	require.NoError(t, err)
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig
}

type jsonRPCReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  []any           `json:"params"`
}

type jsonRPCResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func postJSONRPC(t *testing.T, url string, authHeader string, payload any) (*http.Response, []byte) {
	t.Helper()
	raw, err := json.Marshal(payload)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp, body
}

func TestParametersValidation(t *testing.T) {
	ctx := context.Background()
	monitor := nullmetrics.New()
	validPrimary := &executionproxy.EndpointConfig{Name: "besu", URL: "http://127.0.0.1:8551"}

	tests := []struct {
		name   string
		params []standard.Parameter
		err    string
	}{
		{
			name: "MonitorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithListenAddress("127.0.0.1:0"),
				standard.WithPrimaryEL(validPrimary),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "ListenAddressMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithPrimaryEL(validPrimary),
			},
			err: "problem with parameters: no listen address specified",
		},
		{
			name: "ListenAddressMalformed",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithListenAddress("not-a-host-port"),
				standard.WithPrimaryEL(validPrimary),
			},
			err: "listen address malformed",
		},
		{
			name: "PrimaryMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithListenAddress("127.0.0.1:0"),
			},
			err: "problem with parameters: no primary execution client specified",
		},
		{
			name: "PrimaryMalformedURL",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithListenAddress("127.0.0.1:0"),
				standard.WithPrimaryEL(&executionproxy.EndpointConfig{URL: "ftp://bad"}),
			},
			err: "invalid primary execution client",
		},
		{
			name: "SecondaryNilEntry",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithListenAddress("127.0.0.1:0"),
				standard.WithPrimaryEL(validPrimary),
				standard.WithSecondaryELs([]*executionproxy.EndpointConfig{nil}),
			},
			err: "secondary execution client at index 0 is nil",
		},
		{
			name: "InvalidIncomingJWTSecretLength",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithListenAddress("127.0.0.1:0"),
				standard.WithPrimaryEL(validPrimary),
				standard.WithIncomingJWTSecret([]byte{1, 2, 3}),
			},
			err: "incoming JWT secret must be 32 bytes",
		},
		{
			name: "InvalidTimeout",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(monitor),
				standard.WithListenAddress("127.0.0.1:0"),
				standard.WithPrimaryEL(validPrimary),
				standard.WithTimeout(0),
			},
			err: "timeout must be positive",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, err := standard.New(ctx, tc.params...)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.err)
			require.Nil(t, svc)
		})
	}
}

func TestNewPayloadAllAgreeAcrossVersions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const samplePreBAL = "0xf90102a0112233"
	const blockHash = "0x3e18feb8a184a98f19be843d6f3fe128d1834be58ec3f61d58e0953f5d51b80a"
	const parentHash = "0x56e867cc0cd639d6b583cfd066b4a6864524ef309566197932490e3fb656825a"

	var primaryCalls atomic.Int32
	var sec1Calls atomic.Int32
	var sec2Calls atomic.Int32

	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls.Add(1)
		var req jsonRPCReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))

		switch req.Method {
		case "engine_newPayloadV1", "engine_newPayloadV2":
			require.Len(t, req.Params, 2)
			require.Equal(t, true, req.Params[1])
		case "engine_newPayloadV3":
			require.Len(t, req.Params, 4)
			require.Equal(t, true, req.Params[3])
		case "engine_newPayloadV4", "engine_newPayloadV5":
			require.Len(t, req.Params, 5)
			require.Equal(t, true, req.Params[4])
		case "engine_newPayloadV6":
			require.Len(t, req.Params, 6)
			require.Equal(t, true, req.Params[5])
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"status":"VALID","latestValidHash":%q,"validationError":null,"inclusionListSatisfied":true,"pre_bal":%q}}`,
				string(req.ID), blockHash, samplePreBAL)
			return
		case "eth_chainId":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":"0x1"}`, string(req.ID))
			return
		default:
			t.Fatalf("unexpected method on primary: %s", req.Method)
		}

		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"status":"VALID","latestValidHash":%q,"validationError":null,"pre_bal":%q}}`,
			string(req.ID), blockHash, samplePreBAL)
	}))
	defer primaryServer.Close()

	makeConsumer := func(counter *atomic.Int32) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			counter.Add(1)
			var req jsonRPCReq
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))

			n := len(req.Params)
			require.GreaterOrEqual(t, n, 3)
			require.Equal(t, false, req.Params[n-2])
			require.Equal(t, samplePreBAL, req.Params[n-1])

			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"status":"VALID","latestValidHash":%q,"validationError":null}}`,
				string(req.ID), blockHash)
		}))
	}
	sec1 := makeConsumer(&sec1Calls)
	defer sec1.Close()
	sec2 := makeConsumer(&sec2Calls)
	defer sec2.Close()

	proxySvc, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(nullmetrics.New()),
		standard.WithListenAddress("127.0.0.1:0"),
		standard.WithPrimaryEL(&executionproxy.EndpointConfig{Name: "besu", URL: primaryServer.URL}),
		standard.WithSecondaryELs([]*executionproxy.EndpointConfig{
			{Name: "geth", URL: sec1.URL},
			{Name: "reth", URL: sec2.URL},
		}),
	)
	require.NoError(t, err)
	proxyURL := "http://" + proxySvc.ListenAddress()

	payloadObj := map[string]any{
		"parentHash":  parentHash,
		"blockHash":   blockHash,
		"blockNumber": "0x2",
	}

	versionCases := []struct {
		method string
		params []any
	}{
		{"engine_newPayloadV1", []any{payloadObj}},
		{"engine_newPayloadV2", []any{payloadObj}},
		{"engine_newPayloadV3", []any{payloadObj, []string{}, parentHash}},
		{"engine_newPayloadV4", []any{payloadObj, []string{}, parentHash, []string{}}},
		{"engine_newPayloadV5", []any{payloadObj, []string{}, parentHash, []string{}}},
		{"engine_newPayloadV6", []any{payloadObj, []string{}, parentHash, []string{}, []string{}}},
	}

	for i, tc := range versionCases {
		httpResp, body := postJSONRPC(t, proxyURL, "", map[string]any{
			"jsonrpc": "2.0",
			"id":      i + 1,
			"method":  tc.method,
			"params":  tc.params,
		})
		require.Equal(t, http.StatusOK, httpResp.StatusCode)

		var rpcResp jsonRPCResp
		require.NoError(t, json.Unmarshal(body, &rpcResp))
		require.Nil(t, rpcResp.Error)

		var statusMap map[string]any
		require.NoError(t, json.Unmarshal(rpcResp.Result, &statusMap))
		require.Equal(t, "VALID", statusMap["status"])
		require.Equal(t, blockHash, statusMap["latestValidHash"])
		// Ensure pre_bal is stripped before forwarding back to a standard consensus client.
		require.NotContains(t, statusMap, "pre_bal")
		if tc.method == "engine_newPayloadV6" {
			require.Equal(t, true, statusMap["inclusionListSatisfied"])
		}
	}

	require.Equal(t, int32(len(versionCases)), primaryCalls.Load())
	require.Equal(t, int32(len(versionCases)), sec1Calls.Load())
	require.Equal(t, int32(len(versionCases)), sec2Calls.Load())

	// Non-newPayload RPC calls should only go to primary EL, never secondary ELs.
	httpResp, body := postJSONRPC(t, proxyURL, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      99,
		"method":  "eth_chainId",
		"params":  []any{},
	})
	require.Equal(t, http.StatusOK, httpResp.StatusCode)
	var chainIDResp jsonRPCResp
	require.NoError(t, json.Unmarshal(body, &chainIDResp))
	require.Equal(t, `"0x1"`, string(chainIDResp.Result))
	require.Equal(t, int32(len(versionCases)), sec1Calls.Load())
}

func TestSecondaryDisagreementBlocksForkchoiceAndDescendants(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const parentHash = "0x1111111111111111111111111111111111111111111111111111111111111111"
	const badBlockHash = "0x2222222222222222222222222222222222222222222222222222222222222222"
	const childBlockHash = "0x3333333333333333333333333333333333333333333333333333333333333333"

	var primaryFCUCalls atomic.Int32
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		if req.Method == "engine_forkchoiceUpdatedV3" {
			primaryFCUCalls.Add(1)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"payloadStatus":{"status":"VALID","latestValidHash":%q,"validationError":null},"payloadId":null}}`,
				string(req.ID), badBlockHash)
			return
		}
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"status":"VALID","latestValidHash":%q,"validationError":null,"pre_bal":"0xc380c0c0"}}`,
			string(req.ID), badBlockHash)
	}))
	defer primaryServer.Close()

	secAgree := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"status":"VALID","latestValidHash":%q,"validationError":null}}`,
			string(req.ID), badBlockHash)
	}))
	defer secAgree.Close()

	secReject := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"status":"INVALID","latestValidHash":%q,"validationError":"receiptsRoot mismatch"}}`,
			string(req.ID), parentHash)
	}))
	defer secReject.Close()

	proxySvc, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(nullmetrics.New()),
		standard.WithListenAddress("127.0.0.1:0"),
		standard.WithPrimaryEL(&executionproxy.EndpointConfig{Name: "besu", URL: primaryServer.URL}),
		standard.WithSecondaryELs([]*executionproxy.EndpointConfig{
			{Name: "geth", URL: secAgree.URL},
			{Name: "reth", URL: secReject.URL},
		}),
	)
	require.NoError(t, err)
	proxyURL := "http://" + proxySvc.ListenAddress()

	// 1. Send engine_newPayloadV4 -> secondary rejects with INVALID.
	_, body := postJSONRPC(t, proxyURL, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "engine_newPayloadV4",
		"params": []any{
			map[string]any{"parentHash": parentHash, "blockHash": badBlockHash, "blockNumber": "0x10"},
			[]string{},
			parentHash,
			[]string{},
		},
	})
	var npResp jsonRPCResp
	require.NoError(t, json.Unmarshal(body, &npResp))
	require.Nil(t, npResp.Error)
	var status map[string]any
	require.NoError(t, json.Unmarshal(npResp.Result, &status))
	require.Equal(t, "INVALID", status["status"])
	require.Equal(t, parentHash, status["latestValidHash"])
	require.Contains(t, status["validationError"], "reth: receiptsRoot mismatch")

	// 2. Consensus client attempts engine_forkchoiceUpdatedV3 with headBlockHash = badBlockHash -> blocked!
	_, fcuBody := postJSONRPC(t, proxyURL, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "engine_forkchoiceUpdatedV3",
		"params": []any{
			map[string]any{
				"headBlockHash":      badBlockHash,
				"safeBlockHash":      parentHash,
				"finalizedBlockHash": parentHash,
			},
			nil,
		},
	})
	require.Equal(t, int32(0), primaryFCUCalls.Load())
	var fcuResp jsonRPCResp
	require.NoError(t, json.Unmarshal(fcuBody, &fcuResp))
	var fcuResult map[string]any
	require.NoError(t, json.Unmarshal(fcuResp.Result, &fcuResult))
	ps := fcuResult["payloadStatus"].(map[string]any)
	require.Equal(t, "INVALID", ps["status"])
	require.Equal(t, parentHash, ps["latestValidHash"])

	// 3. Descendant block building on badBlockHash is immediately rejected with latestValidHash = parentHash!
	_, childBody := postJSONRPC(t, proxyURL, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "engine_newPayloadV4",
		"params": []any{
			map[string]any{"parentHash": badBlockHash, "blockHash": childBlockHash, "blockNumber": "0x11"},
			[]string{},
			parentHash,
			[]string{},
		},
	})
	var childResp jsonRPCResp
	require.NoError(t, json.Unmarshal(childBody, &childResp))
	var childStatus map[string]any
	require.NoError(t, json.Unmarshal(childResp.Result, &childStatus))
	require.Equal(t, "INVALID", childStatus["status"])
	require.Equal(t, parentHash, childStatus["latestValidHash"])
}

func TestSecondaryTransientFailureHoldsForkchoiceUntilRetrySucceeds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const parentHash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const blockHash = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	var primaryFCUCalls atomic.Int32
	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		if req.Method == "engine_forkchoiceUpdatedV3" {
			primaryFCUCalls.Add(1)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"payloadStatus":{"status":"VALID","latestValidHash":%q,"validationError":null},"payloadId":null}}`,
				string(req.ID), blockHash)
			return
		}
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"status":"VALID","latestValidHash":%q,"validationError":null,"pre_bal":"0xc380c0c0"}}`,
			string(req.ID), blockHash)
	}))
	defer primaryServer.Close()

	var secondaryHealthy atomic.Bool
	secondaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !secondaryHealthy.Load() {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		var req jsonRPCReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"status":"VALID","latestValidHash":%q,"validationError":null}}`,
			string(req.ID), blockHash)
	}))
	defer secondaryServer.Close()

	proxySvc, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(nullmetrics.New()),
		standard.WithListenAddress("127.0.0.1:0"),
		standard.WithPrimaryEL(&executionproxy.EndpointConfig{Name: "besu", URL: primaryServer.URL}),
		standard.WithSecondaryELs([]*executionproxy.EndpointConfig{
			{Name: "erigon", URL: secondaryServer.URL},
		}),
	)
	require.NoError(t, err)
	proxyURL := "http://" + proxySvc.ListenAddress()

	newPayloadReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      10,
		"method":  "engine_newPayloadV4",
		"params": []any{
			map[string]any{"parentHash": parentHash, "blockHash": blockHash, "blockNumber": "0x5"},
			[]string{},
			parentHash,
			[]string{},
		},
	}

	// 1. Secondary returns HTTP 503 -> proxy returns JSON-RPC error (not INVALID).
	_, body := postJSONRPC(t, proxyURL, "", newPayloadReq)
	var errResp jsonRPCResp
	require.NoError(t, json.Unmarshal(body, &errResp))
	require.NotNil(t, errResp.Error)
	require.Contains(t, errResp.Error.Message, "erigon")

	// 2. Consensus client calls forkchoiceUpdated on unverified head -> proxy returns SYNCING without calling primary FCU.
	fcuReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      11,
		"method":  "engine_forkchoiceUpdatedV3",
		"params": []any{
			map[string]any{
				"headBlockHash":      blockHash,
				"safeBlockHash":      parentHash,
				"finalizedBlockHash": parentHash,
			},
			nil,
		},
	}
	_, fcuBody := postJSONRPC(t, proxyURL, "", fcuReq)
	require.Equal(t, int32(0), primaryFCUCalls.Load())
	var fcuResp jsonRPCResp
	require.NoError(t, json.Unmarshal(fcuBody, &fcuResp))
	var fcuResult map[string]any
	require.NoError(t, json.Unmarshal(fcuResp.Result, &fcuResult))
	require.Equal(t, "SYNCING", fcuResult["payloadStatus"].(map[string]any)["status"])

	// 3. Secondary recovers; retry newPayload -> VALID, then forkchoiceUpdated -> forwarded to primary and VALID!
	secondaryHealthy.Store(true)
	_, retryBody := postJSONRPC(t, proxyURL, "", newPayloadReq)
	var retryResp jsonRPCResp
	require.NoError(t, json.Unmarshal(retryBody, &retryResp))
	require.Nil(t, retryResp.Error)

	_, fcuBody2 := postJSONRPC(t, proxyURL, "", fcuReq)
	require.Equal(t, int32(1), primaryFCUCalls.Load())
	require.NoError(t, json.Unmarshal(fcuBody2, &fcuResp))
	require.NoError(t, json.Unmarshal(fcuResp.Result, &fcuResult))
	require.Equal(t, "VALID", fcuResult["payloadStatus"].(map[string]any)["status"])
}

func TestJWTAuthenticationAndGzipAndBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clSecret := makeSecret(0x11)
	defaultELSecret := makeSecret(0x22)
	secOverrideSecret := makeSecret(0x33)

	const blockHash = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	const parentHash = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify primary received JWT signed with defaultELSecret.
		auth := r.Header.Get("Authorization")
		require.True(t, len(auth) > 7)
		var req jsonRPCReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		if req.Method == "eth_blockNumber" {
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":"0x2a"}`, string(req.ID))
			return
		}
		// Verify signature matches defaultELSecret.
		parts := bytes.Split([]byte(auth[7:]), []byte("."))
		require.Len(t, parts, 3)
		mac := hmac.New(sha256.New, defaultELSecret)
		mac.Write(parts[0])
		mac.Write([]byte("."))
		mac.Write(parts[1])
		expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		require.Equal(t, expectedSig, string(parts[2]))

		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"status":"VALID","latestValidHash":%q,"validationError":null,"pre_bal":"0xc380c0c0"}}`,
			string(req.ID), blockHash)
	}))
	defer primaryServer.Close()

	secondaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify secondary received JWT signed with secOverrideSecret.
		auth := r.Header.Get("Authorization")
		require.True(t, len(auth) > 7)
		parts := bytes.Split([]byte(auth[7:]), []byte("."))
		require.Len(t, parts, 3)
		mac := hmac.New(sha256.New, secOverrideSecret)
		mac.Write(parts[0])
		mac.Write([]byte("."))
		mac.Write(parts[1])
		expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		require.Equal(t, expectedSig, string(parts[2]))

		var req jsonRPCReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"status":"VALID","latestValidHash":%q,"validationError":null}}`,
			string(req.ID), blockHash)
	}))
	defer secondaryServer.Close()

	proxySvc, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(nullmetrics.New()),
		standard.WithListenAddress("127.0.0.1:0"),
		standard.WithIncomingJWTSecret(clSecret),
		standard.WithDefaultJWTSecret(defaultELSecret),
		standard.WithPrimaryEL(&executionproxy.EndpointConfig{Name: "besu", URL: primaryServer.URL}),
		standard.WithSecondaryELs([]*executionproxy.EndpointConfig{
			{Name: "nethermind", URL: secondaryServer.URL, JWTSecret: secOverrideSecret},
		}),
	)
	require.NoError(t, err)
	proxyURL := "http://" + proxySvc.ListenAddress()

	// 1. Missing JWT -> 401.
	httpResp, _ := postJSONRPC(t, proxyURL, "", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"})
	require.Equal(t, http.StatusUnauthorized, httpResp.StatusCode)

	// 2. Expired JWT -> 401.
	expiredToken := mintTestJWT(t, clSecret, time.Now().Add(-2*time.Minute).Unix())
	httpResp, _ = postJSONRPC(t, proxyURL, "Bearer "+expiredToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"})
	require.Equal(t, http.StatusUnauthorized, httpResp.StatusCode)

	// 3. Valid JWT + Gzip-compressed JSON-RPC batch containing newPayloadV2 + eth_blockNumber!
	validToken := mintTestJWT(t, clSecret, time.Now().Unix())
	batchPayload := []any{
		map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "engine_newPayloadV2",
			"params":  []any{map[string]any{"parentHash": parentHash, "blockHash": blockHash, "blockNumber": "0x3"}},
		},
		map[string]any{
			"jsonrpc": "2.0",
			"id":      2,
			"method":  "eth_blockNumber",
			"params":  []any{},
		},
	}
	rawBatch, err := json.Marshal(batchPayload)
	require.NoError(t, err)
	var gzBuf bytes.Buffer
	gzWriter := gzip.NewWriter(&gzBuf)
	_, err = gzWriter.Write(rawBatch)
	require.NoError(t, err)
	require.NoError(t, gzWriter.Close())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL, &gzBuf)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+validToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	respBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var batchResp []jsonRPCResp
	require.NoError(t, json.Unmarshal(respBytes, &batchResp))
	require.Len(t, batchResp, 2)
	require.Nil(t, batchResp[0].Error)
	require.Equal(t, `"0x2a"`, string(batchResp[1].Result))

	// 4. Reject alg:none JWT tokens.
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"none"}`))
	noneClaims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iat":%d}`, time.Now().Unix())))
	httpResp, _ = postJSONRPC(t, proxyURL, "Bearer "+noneHeader+"."+noneClaims+".", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"})
	require.Equal(t, http.StatusUnauthorized, httpResp.StatusCode)
}

func TestEdgeCasesMissingPreBALPassThroughAuthAndPriority(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const parentHash = "0x1010101010101010101010101010101010101010101010101010101010101010"
	const blockHash1 = "0x2020202020202020202020202020202020202020202020202020202020202020"
	const blockHash2 = "0x3030303030303030303030303030303030303030303030303030303030303030"
	const blockHash3 = "0x4040404040404040404040404040404040404040404040404040404040404040"

	var primaryAuthSeen atomic.Value
	var secondaryAuthSeen atomic.Value
	var secondaryCalls atomic.Int32

	primaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryAuthSeen.Store(r.Header.Get("Authorization"))
		var req jsonRPCReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		payload := req.Params[0].(map[string]any)
		switch payload["blockHash"] {
		case blockHash1:
			// Primary omits pre_bal despite returning VALID.
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"status":"VALID","latestValidHash":%q,"validationError":null}}`,
				string(req.ID), blockHash1)
		case blockHash2:
			// Primary returns SYNCING -> secondaries must NOT be called.
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"status":"SYNCING","latestValidHash":null,"validationError":null}}`,
				string(req.ID))
		case blockHash3:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"status":"VALID","latestValidHash":%q,"validationError":null,"pre_bal":"0xc380c0c0"}}`,
				string(req.ID), blockHash3)
		}
	}))
	defer primaryServer.Close()

	// Secondary 1 errors out with HTTP 500, while Secondary 2 explicitly returns INVALID.
	// Explicit INVALID must take precedence over transient HTTP 500!
	secFlaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondaryCalls.Add(1)
		secondaryAuthSeen.Store(r.Header.Get("Authorization"))
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer secFlaky.Close()

	secInvalid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondaryCalls.Add(1)
		var req jsonRPCReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"status":"INVALID","latestValidHash":%q,"validationError":"unused pre_bal account"}}`,
			string(req.ID), parentHash)
	}))
	defer secInvalid.Close()

	proxySvc, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithMonitor(nullmetrics.New()),
		standard.WithListenAddress("127.0.0.1:0"),
		standard.WithPrimaryEL(&executionproxy.EndpointConfig{Name: "besu", URL: primaryServer.URL}),
		standard.WithSecondaryELs([]*executionproxy.EndpointConfig{
			{Name: "flaky-consumer", URL: secFlaky.URL},
			{Name: "strict-consumer", URL: secInvalid.URL},
		}),
	)
	require.NoError(t, err)
	proxyURL := "http://" + proxySvc.ListenAddress()

	// Case 1: Primary returns VALID without pre_bal -> RPC error (-32603), secondaries not called.
	_, body1 := postJSONRPC(t, proxyURL, "Bearer passthrough-token", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "engine_newPayloadV1",
		"params":  []any{map[string]any{"parentHash": parentHash, "blockHash": blockHash1, "blockNumber": "0x1"}},
	})
	var resp1 jsonRPCResp
	require.NoError(t, json.Unmarshal(body1, &resp1))
	require.NotNil(t, resp1.Error)
	require.Contains(t, resp1.Error.Message, "without pre_bal")
	require.Equal(t, int32(0), secondaryCalls.Load())
	require.Equal(t, "Bearer passthrough-token", primaryAuthSeen.Load())

	// Case 2: Primary returns SYNCING -> forwarded directly without calling secondaries.
	_, body2 := postJSONRPC(t, proxyURL, "Bearer passthrough-token", map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "engine_newPayloadV1",
		"params":  []any{map[string]any{"parentHash": parentHash, "blockHash": blockHash2, "blockNumber": "0x2"}},
	})
	var resp2 jsonRPCResp
	require.NoError(t, json.Unmarshal(body2, &resp2))
	require.Nil(t, resp2.Error)
	require.Contains(t, string(resp2.Result), `"SYNCING"`)
	require.Equal(t, int32(0), secondaryCalls.Load())

	// Case 3: One secondary HTTP 500 + one secondary INVALID -> INVALID wins, pass-through auth forwarded.
	_, body3 := postJSONRPC(t, proxyURL, "Bearer passthrough-token", map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "engine_newPayloadV1",
		"params":  []any{map[string]any{"parentHash": parentHash, "blockHash": blockHash3, "blockNumber": "0x3"}},
	})
	var resp3 jsonRPCResp
	require.NoError(t, json.Unmarshal(body3, &resp3))
	require.Nil(t, resp3.Error)
	require.Contains(t, string(resp3.Result), `"INVALID"`)
	require.Contains(t, string(resp3.Result), "unused pre_bal account")
	require.Equal(t, "Bearer passthrough-token", secondaryAuthSeen.Load())
}
