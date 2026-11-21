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

// Package standard provides the standard Pre-BAL execution layer verification proxy.
package standard

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/attestantio/vouch/services/executionproxy"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

const (
	jsonRPCVersion       = "2.0"
	rpcParseErrorCode    = -32700
	rpcInvalidReqCode    = -32600
	rpcInvalidParamsCode = -32602
	rpcInternalErrorCode = -32603

	statusValid            = "VALID"
	statusInvalid          = "INVALID"
	statusInvalidBlockHash = "INVALID_BLOCK_HASH"
	statusSyncing          = "SYNCING"
)

var _ executionproxy.Service = (*Service)(nil)

// Service is the standard execution layer proxy service.
type Service struct {
	log               zerolog.Logger
	monitor           metrics.Service
	primaryEL         *executionproxy.EndpointConfig
	secondaryELs      []*executionproxy.EndpointConfig
	incomingJWTSecret []byte
	defaultJWTSecret  []byte
	httpClient        *http.Client
	server            *http.Server
	tracker           *blockTracker
	boundAddress      string
	timeout           time.Duration
	maxBodyBytes      int64
	shutdownOnce      sync.Once
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type executionPayloadMeta struct {
	ParentHash  string `json:"parentHash"`  //nolint:tagliatelle
	BlockHash   string `json:"blockHash"`   //nolint:tagliatelle
	BlockNumber string `json:"blockNumber"` //nolint:tagliatelle
}

type payloadStatusView struct {
	Status          string          `json:"status"`
	LatestValidHash json.RawMessage `json:"latestValidHash"` //nolint:tagliatelle
	ValidationError *string         `json:"validationError"` //nolint:tagliatelle
	PreBAL          *string         `json:"pre_bal"`
}

type payloadStatusResponse struct {
	Status          string          `json:"status"`
	LatestValidHash json.RawMessage `json:"latestValidHash"` //nolint:tagliatelle
	ValidationError *string         `json:"validationError"` //nolint:tagliatelle
}

type forkchoiceStateMeta struct {
	HeadBlockHash      string `json:"headBlockHash"`      //nolint:tagliatelle
	SafeBlockHash      string `json:"safeBlockHash"`      //nolint:tagliatelle
	FinalizedBlockHash string `json:"finalizedBlockHash"` //nolint:tagliatelle
}

type forkchoiceUpdatedResponse struct {
	PayloadStatus payloadStatusResponse `json:"payloadStatus"` //nolint:tagliatelle
	PayloadID     json.RawMessage       `json:"payloadId"`     //nolint:tagliatelle
}

type secondaryResult struct {
	clientName      string
	status          string
	latestValidHash json.RawMessage
	validationError string
	rpcErr          *rpcError
	err             error
}

// New creates and starts a new execution layer verification proxy service.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	log := zerologger.With().Str("service", "executionproxy").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	if err := registerMetrics(ctx, parameters.monitor); err != nil {
		return nil, errors.Wrap(err, "failed to register metrics")
	}

	var listenCfg net.ListenConfig
	listener, err := listenCfg.Listen(ctx, "tcp", parameters.listenAddress)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to listen on %s", parameters.listenAddress)
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	s := &Service{
		log:               log,
		monitor:           parameters.monitor,
		primaryEL:         parameters.primaryEL,
		secondaryELs:      parameters.secondaryELs,
		incomingJWTSecret: parameters.incomingJWTSecret,
		defaultJWTSecret:  parameters.defaultJWTSecret,
		httpClient: &http.Client{
			Transport: transport,
		},
		tracker:      newBlockTracker(defaultTrackedBlocksCap),
		boundAddress: listener.Addr().String(),
		timeout:      parameters.timeout,
		maxBodyBytes: parameters.maxBodyBytes,
	}

	server := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.server = server

	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			s.log.Error().Err(serveErr).Str("listen_address", s.boundAddress).Msg("Execution proxy HTTP server stopped unexpectedly")
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := s.Shutdown(shutdownCtx); shutdownErr != nil {
			s.log.Warn().Err(shutdownErr).Msg("Failed to shut down execution proxy cleanly")
		}
	}()

	s.log.Info().
		Str("listen_address", s.boundAddress).
		Str("primary_el", s.primaryEL.Name).
		Int("secondary_els", len(s.secondaryELs)).
		Msg("Started execution layer Pre-BAL verification proxy")

	return s, nil
}

// ListenAddress returns the bound TCP address (host:port) of the proxy server.
func (s *Service) ListenAddress() string {
	return s.boundAddress
}

// Shutdown gracefully stops the proxy HTTP server.
func (s *Service) Shutdown(ctx context.Context) error {
	var shutdownErr error
	s.shutdownOnce.Do(func() {
		shutdownErr = s.server.Shutdown(ctx)
		s.httpClient.CloseIdleConnections()
	})

	return shutdownErr
}

// ServeHTTP handles incoming consensus client JSON-RPC requests.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	incomingAuth := r.Header.Get("Authorization")
	if len(s.incomingJWTSecret) > 0 {
		if err := verifyAuthorizationHeader(incomingAuth, s.incomingJWTSecret, time.Now()); err != nil {
			s.log.Warn().Err(err).Msg("Rejected unauthorized Engine API request")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	bodyBytes, statusCode, err := readDecompressedBody(r.Body, r.Header.Get("Content-Encoding"), s.maxBodyBytes)
	if err != nil {
		s.log.Warn().Err(err).Msg("Failed to read request body")
		http.Error(w, err.Error(), statusCode)
		return
	}

	trimmed := bytes.TrimSpace(bodyBytes)
	if len(trimmed) == 0 {
		writeJSONResponse(w, makeErrorResponse(nil, rpcParseErrorCode, "Parse error"))
		return
	}

	if trimmed[0] == '[' {
		s.handleBatch(r.Context(), w, trimmed, incomingAuth)
		return
	}

	var req rpcRequest
	if err := json.Unmarshal(trimmed, &req); err != nil {
		writeJSONResponse(w, makeErrorResponse(nil, rpcParseErrorCode, "Parse error"))
		return
	}
	if req.Method == "" {
		writeJSONResponse(w, makeErrorResponse(req.ID, rpcInvalidReqCode, "Invalid Request"))
		return
	}

	resp, isNotification := s.dispatchSingle(r.Context(), &req, trimmed, incomingAuth)
	if isNotification {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSONResponse(w, resp)
}

func (s *Service) handleBatch(ctx context.Context, w http.ResponseWriter, rawBatch []byte, incomingAuth string) {
	var rawItems []json.RawMessage
	if err := json.Unmarshal(rawBatch, &rawItems); err != nil {
		writeJSONResponse(w, makeErrorResponse(nil, rpcParseErrorCode, "Parse error"))
		return
	}
	if len(rawItems) == 0 {
		writeJSONResponse(w, makeErrorResponse(nil, rpcInvalidReqCode, "Invalid Request"))
		return
	}

	responses := make([]rpcResponse, 0, len(rawItems))
	for _, item := range rawItems {
		var req rpcRequest
		if err := json.Unmarshal(item, &req); err != nil {
			responses = append(responses, makeErrorResponse(nil, rpcInvalidReqCode, "Invalid Request"))
			continue
		}
		if req.Method == "" {
			responses = append(responses, makeErrorResponse(req.ID, rpcInvalidReqCode, "Invalid Request"))
			continue
		}
		resp, isNotification := s.dispatchSingle(ctx, &req, item, incomingAuth)
		if !isNotification {
			responses = append(responses, resp)
		}
	}

	if len(responses) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(responses); err != nil {
		s.log.Warn().Err(err).Msg("Failed to write JSON-RPC batch response")
	}
}

func (s *Service) dispatchSingle(
	ctx context.Context,
	req *rpcRequest,
	rawReq []byte,
	incomingAuth string,
) (rpcResponse, bool) {
	started := time.Now()
	isNotification := len(req.ID) == 0

	if baseParams, isNewPayload := newPayloadBaseParams(req.Method); isNewPayload {
		resp, outcome := s.handleNewPayload(ctx, req, baseParams, incomingAuth)
		monitorProxyRequest(req.Method, outcome, time.Since(started))
		return resp, isNotification
	}

	if strings.HasPrefix(req.Method, "engine_forkchoiceUpdatedV") {
		resp, outcome := s.handleForkchoiceUpdated(ctx, req, rawReq, incomingAuth)
		monitorProxyRequest(req.Method, outcome, time.Since(started))
		return resp, isNotification
	}

	resp, outcome := s.forwardRawToPrimary(ctx, req, rawReq, incomingAuth)
	monitorProxyRequest(req.Method, outcome, time.Since(started))
	return resp, isNotification
}

func newPayloadBaseParams(method string) (int, bool) {
	switch method {
	case "engine_newPayloadV1", "engine_newPayloadV2":
		return 1, true
	case "engine_newPayloadV3":
		return 3, true
	case "engine_newPayloadV4", "engine_newPayloadV5":
		return 4, true
	case "engine_newPayloadV6":
		return 5, true
	default:
		return 0, false
	}
}

func (s *Service) handleNewPayload(
	ctx context.Context,
	req *rpcRequest,
	baseParams int,
	incomingAuth string,
) (rpcResponse, string) {
	var params []json.RawMessage
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return makeErrorResponse(req.ID, rpcInvalidParamsCode, "Invalid params"), "invalid_params"
	}
	if len(params) < baseParams || len(params) > baseParams+2 {
		return makeErrorResponse(req.ID, rpcInvalidParamsCode,
			fmt.Sprintf("Invalid params: expected %d parameters, got %d", baseParams, len(params))), "invalid_params"
	}

	callerProducePreBAL := false
	if len(params) > baseParams && !isJSONNull(params[baseParams]) {
		if err := json.Unmarshal(params[baseParams], &callerProducePreBAL); err != nil {
			return makeErrorResponse(req.ID, rpcInvalidParamsCode, "Invalid produce_pre_bal parameter"), "invalid_params"
		}
	}
	if len(params) > baseParams+1 && !isJSONNull(params[baseParams+1]) && callerProducePreBAL {
		return makeErrorResponse(req.ID, rpcInvalidParamsCode, "Cannot set produce_pre_bal when pre_bal is provided"), "invalid_params"
	}

	var meta executionPayloadMeta
	_ = json.Unmarshal(params[0], &meta)

	// Reject blocks that build directly on an ancestor already proven INVALID by a secondary EL.
	if parentRejected, isRejected := s.tracker.lookupRejected(meta.ParentHash); isRejected {
		errMsg := fmt.Sprintf("ancestor block %s failed secondary Pre-BAL verification: %s",
			meta.ParentHash, parentRejected.validationError)
		lvh := parentRejected.latestValidHash
		if len(lvh) == 0 {
			lvh = json.RawMessage("null")
		}
		s.tracker.markRejected(meta.BlockHash, rejectedBlock{
			status:          statusInvalid,
			latestValidHash: lvh,
			validationError: errMsg,
		})
		s.log.Warn().
			Str("block_hash", meta.BlockHash).
			Str("parent_hash", meta.ParentHash).
			Msg("Rejecting payload descending from previously rejected parent")
		monitorVerification("disagreement")
		return makePayloadStatusResponse(req.ID, statusInvalid, lvh, &errMsg), "disagreement"
	}

	// 1. Send engine_newPayloadV* with produce_pre_bal = true to the primary EL.
	primaryParams := make([]json.RawMessage, baseParams+1)
	copy(primaryParams, params[:baseParams])
	primaryParams[baseParams] = json.RawMessage("true")

	primaryParamsBytes, err := json.Marshal(primaryParams)
	if err != nil {
		return makeErrorResponse(req.ID, rpcInternalErrorCode, "Failed to encode primary parameters"), "error"
	}

	primaryReq := rpcRequest{
		JSONRPC: jsonRPCVersion,
		ID:      effectiveID(req.ID),
		Method:  req.Method,
		Params:  primaryParamsBytes,
	}
	primaryReqBytes, err := json.Marshal(primaryReq)
	if err != nil {
		return makeErrorResponse(req.ID, rpcInternalErrorCode, "Failed to encode primary request"), "error"
	}

	primaryResp, err := s.callJSONRPC(ctx, "primary", s.primaryEL, primaryReqBytes, incomingAuth)
	if err != nil {
		s.log.Error().Err(err).Str("primary_el", s.primaryEL.Name).Str("block_hash", meta.BlockHash).Msg("Primary execution client call failed")
		return makeErrorResponse(req.ID, rpcInternalErrorCode,
			fmt.Sprintf("primary execution client %s failed: %v", s.primaryEL.Name, err)), "primary_error"
	}
	if primaryResp.Error != nil {
		return rpcResponse{
			JSONRPC: jsonRPCVersion,
			ID:      effectiveID(req.ID),
			Error:   primaryResp.Error,
		}, "primary_rpc_error"
	}

	var statusView payloadStatusView
	if err := json.Unmarshal(primaryResp.Result, &statusView); err != nil {
		s.log.Error().Err(err).Str("primary_el", s.primaryEL.Name).Msg("Primary execution client returned malformed PayloadStatus")
		return makeErrorResponse(req.ID, rpcInternalErrorCode, "primary execution client returned malformed PayloadStatus"), "primary_error"
	}

	var resultMap map[string]json.RawMessage
	if err := json.Unmarshal(primaryResp.Result, &resultMap); err != nil {
		return makeErrorResponse(req.ID, rpcInternalErrorCode, "primary execution client returned non-object PayloadStatus"), "primary_error"
	}

	// Non-VALID statuses (SYNCING, ACCEPTED, INVALID, INVALID_BLOCK_HASH) have no Pre-BAL to verify on consumers.
	if statusView.Status != statusValid {
		if statusView.Status == statusInvalid || statusView.Status == statusInvalidBlockHash {
			errMsg := ""
			if statusView.ValidationError != nil {
				errMsg = *statusView.ValidationError
			}
			s.tracker.markRejected(meta.BlockHash, rejectedBlock{
				status:          statusView.Status,
				latestValidHash: statusView.LatestValidHash,
				validationError: errMsg,
			})
		}
		if !callerProducePreBAL {
			delete(resultMap, "pre_bal")
		}
		sanitizedResult, marshalErr := json.Marshal(resultMap)
		if marshalErr != nil {
			sanitizedResult = primaryResp.Result
		}
		return rpcResponse{
			JSONRPC: jsonRPCVersion,
			ID:      effectiveID(req.ID),
			Result:  sanitizedResult,
		}, strings.ToLower(statusView.Status)
	}

	// Primary EL returned VALID: extract pre_bal.
	preBAL := ""
	if statusView.PreBAL != nil {
		preBAL = strings.TrimSpace(*statusView.PreBAL)
	}
	if preBAL == "" && (len(s.secondaryELs) > 0 || callerProducePreBAL) {
		s.tracker.markUnverified(meta.BlockHash)
		monitorVerification("missing_pre_bal")
		s.log.Error().
			Str("primary_el", s.primaryEL.Name).
			Str("block_hash", meta.BlockHash).
			Msg("Primary execution client returned VALID without pre_bal")
		return makeErrorResponse(req.ID, rpcInternalErrorCode,
			fmt.Sprintf("primary execution client %s returned VALID without pre_bal", s.primaryEL.Name)), "missing_pre_bal"
	}

	// 2. Fan out engine_newPayloadV* with produce_pre_bal = false and pre_bal to all secondary ELs.
	if len(s.secondaryELs) > 0 {
		if resp, outcome, ok := s.verifyOnSecondaries(ctx, req, params[:baseParams], preBAL, &meta, incomingAuth); !ok {
			return resp, outcome
		}
	}

	s.tracker.markVerified(meta.BlockHash)
	monitorVerification("verified")
	s.log.Debug().
		Str("block_hash", meta.BlockHash).
		Str("block_number", meta.BlockNumber).
		Int("secondary_els", len(s.secondaryELs)).
		Msg("Execution payload verified by primary and all secondary execution clients")

	if !callerProducePreBAL {
		delete(resultMap, "pre_bal")
	}
	finalResult, err := json.Marshal(resultMap)
	if err != nil {
		return makeErrorResponse(req.ID, rpcInternalErrorCode, "Failed to marshal PayloadStatus"), "error"
	}

	return rpcResponse{
		JSONRPC: jsonRPCVersion,
		ID:      effectiveID(req.ID),
		Result:  finalResult,
	}, "verified"
}

func (s *Service) verifyOnSecondaries(
	ctx context.Context,
	req *rpcRequest,
	coreParams []json.RawMessage,
	preBAL string,
	meta *executionPayloadMeta,
	incomingAuth string,
) (rpcResponse, string, bool) {
	preBALJSON, err := json.Marshal(preBAL)
	if err != nil {
		s.tracker.markUnverified(meta.BlockHash)
		return makeErrorResponse(req.ID, rpcInternalErrorCode, "Failed to encode pre_bal parameter"), "error", false
	}

	secondaryParams := make([]json.RawMessage, len(coreParams)+2)
	copy(secondaryParams, coreParams)
	secondaryParams[len(coreParams)] = json.RawMessage("false")
	secondaryParams[len(coreParams)+1] = preBALJSON

	secondaryParamsBytes, err := json.Marshal(secondaryParams)
	if err != nil {
		s.tracker.markUnverified(meta.BlockHash)
		return makeErrorResponse(req.ID, rpcInternalErrorCode, "Failed to encode secondary parameters"), "error", false
	}

	secondaryReq := rpcRequest{
		JSONRPC: jsonRPCVersion,
		ID:      effectiveID(req.ID),
		Method:  req.Method,
		Params:  secondaryParamsBytes,
	}
	secondaryReqBytes, err := json.Marshal(secondaryReq)
	if err != nil {
		s.tracker.markUnverified(meta.BlockHash)
		return makeErrorResponse(req.ID, rpcInternalErrorCode, "Failed to encode secondary request"), "error", false
	}

	outcomes := make([]secondaryResult, len(s.secondaryELs))
	var wg sync.WaitGroup
	wg.Add(len(s.secondaryELs))
	for i, sec := range s.secondaryELs {
		go func(idx int, endpoint *executionproxy.EndpointConfig) {
			defer wg.Done()
			outcomes[idx] = s.callSecondaryNewPayload(ctx, endpoint, secondaryReqBytes, incomingAuth)
		}(i, sec)
	}
	wg.Wait()

	// Check for explicit INVALID / INVALID_BLOCK_HASH disagreements first (takes priority over transient timeouts).
	var invalidReasons []string
	var firstInvalid *secondaryResult
	var transientErrors []string

	for i := range outcomes {
		outcome := &outcomes[i]
		switch {
		case outcome.err != nil:
			transientErrors = append(transientErrors, fmt.Sprintf("%s: %v", outcome.clientName, outcome.err))
		case outcome.rpcErr != nil:
			transientErrors = append(transientErrors,
				fmt.Sprintf("%s: RPC error %d (%s)", outcome.clientName, outcome.rpcErr.Code, outcome.rpcErr.Message))
		case outcome.status == statusValid:
			// Agreed with primary EL.
		case outcome.status == statusInvalid || outcome.status == statusInvalidBlockHash:
			if firstInvalid == nil {
				firstInvalid = outcome
			}
			detail := outcome.validationError
			if detail == "" {
				detail = outcome.status
			}
			invalidReasons = append(invalidReasons, fmt.Sprintf("%s: %s", outcome.clientName, detail))
		default:
			transientErrors = append(transientErrors, fmt.Sprintf("%s: unexpected status %s", outcome.clientName, outcome.status))
		}
	}

	if firstInvalid != nil {
		outStatus := statusInvalid
		if req.Method == "engine_newPayloadV1" && firstInvalid.status == statusInvalidBlockHash {
			outStatus = statusInvalidBlockHash
		}
		lvh := firstInvalid.latestValidHash
		if len(lvh) == 0 {
			lvh = json.RawMessage("null")
		}
		combinedErr := fmt.Sprintf("secondary execution verification rejected payload (%s)", strings.Join(invalidReasons, "; "))
		s.tracker.markRejected(meta.BlockHash, rejectedBlock{
			status:          outStatus,
			latestValidHash: lvh,
			validationError: combinedErr,
		})
		monitorVerification("disagreement")
		s.log.Error().
			Str("block_hash", meta.BlockHash).
			Str("block_number", meta.BlockNumber).
			Str("disagreements", strings.Join(invalidReasons, "; ")).
			Msg("Secondary execution client disagreed with primary EL and rejected payload")
		return makePayloadStatusResponse(req.ID, outStatus, lvh, &combinedErr), "disagreement", false
	}

	if len(transientErrors) > 0 {
		s.tracker.markUnverified(meta.BlockHash)
		monitorVerification("secondary_error")
		summary := strings.Join(transientErrors, "; ")
		s.log.Error().
			Str("block_hash", meta.BlockHash).
			Str("block_number", meta.BlockNumber).
			Str("errors", summary).
			Msg("Secondary execution verification did not complete across all consumers")
		return makeErrorResponse(req.ID, rpcInternalErrorCode,
			fmt.Sprintf("secondary execution verification failed: %s", summary)), "secondary_error", false
	}

	return rpcResponse{}, "", true
}

func (s *Service) callSecondaryNewPayload(
	ctx context.Context,
	endpoint *executionproxy.EndpointConfig,
	reqBytes []byte,
	incomingAuth string,
) secondaryResult {
	resp, err := s.callJSONRPC(ctx, "secondary", endpoint, reqBytes, incomingAuth)
	if err != nil {
		return secondaryResult{clientName: endpoint.Name, err: err}
	}
	if resp.Error != nil {
		return secondaryResult{clientName: endpoint.Name, rpcErr: resp.Error}
	}

	var statusView payloadStatusView
	if err := json.Unmarshal(resp.Result, &statusView); err != nil {
		return secondaryResult{clientName: endpoint.Name, err: errors.Wrap(err, "malformed PayloadStatus")}
	}
	valErr := ""
	if statusView.ValidationError != nil {
		valErr = *statusView.ValidationError
	}

	return secondaryResult{
		clientName:      endpoint.Name,
		status:          statusView.Status,
		latestValidHash: statusView.LatestValidHash,
		validationError: valErr,
	}
}

func (s *Service) handleForkchoiceUpdated(
	ctx context.Context,
	req *rpcRequest,
	rawReq []byte,
	incomingAuth string,
) (rpcResponse, string) {
	var params []json.RawMessage
	if err := json.Unmarshal(req.Params, &params); err == nil && len(params) >= 1 {
		var fcu forkchoiceStateMeta
		if err := json.Unmarshal(params[0], &fcu); err == nil {
			for _, candidateHash := range []string{fcu.HeadBlockHash, fcu.SafeBlockHash, fcu.FinalizedBlockHash} {
				if rej, isRejected := s.tracker.lookupRejected(candidateHash); isRejected {
					lvh := rej.latestValidHash
					if len(lvh) == 0 {
						lvh = json.RawMessage("null")
					}
					valErr := rej.validationError
					s.log.Error().
						Str("head_block_hash", fcu.HeadBlockHash).
						Str("rejected_hash", candidateHash).
						Msg("Blocking forkchoiceUpdated referencing block rejected by secondary verification")
					return makeForkchoiceResponse(req.ID, statusInvalid, lvh, &valErr), "rejected_head"
				}
			}

			if s.tracker.isUnverified(fcu.HeadBlockHash) {
				s.log.Warn().
					Str("head_block_hash", fcu.HeadBlockHash).
					Msg("Holding back forkchoiceUpdated for head block pending secondary Pre-BAL verification")
				return makeForkchoiceResponse(req.ID, statusSyncing, json.RawMessage("null"), nil), "unverified_head"
			}
		}
	}

	return s.forwardRawToPrimary(ctx, req, rawReq, incomingAuth)
}

func (s *Service) forwardRawToPrimary(
	ctx context.Context,
	req *rpcRequest,
	rawReq []byte,
	incomingAuth string,
) (rpcResponse, string) {
	resp, err := s.callJSONRPC(ctx, "primary", s.primaryEL, rawReq, incomingAuth)
	if err != nil {
		s.log.Error().Err(err).Str("method", req.Method).Str("primary_el", s.primaryEL.Name).Msg("Primary execution client call failed")
		return makeErrorResponse(req.ID, rpcInternalErrorCode,
			fmt.Sprintf("primary execution client %s failed: %v", s.primaryEL.Name, err)), "primary_error"
	}
	resp.ID = effectiveID(req.ID)
	if resp.JSONRPC == "" {
		resp.JSONRPC = jsonRPCVersion
	}
	if resp.Error != nil {
		return resp, "primary_rpc_error"
	}

	return resp, "forwarded"
}

func (s *Service) callJSONRPC(
	ctx context.Context,
	role string,
	endpoint *executionproxy.EndpointConfig,
	body []byte,
	incomingAuth string,
) (rpcResponse, error) {
	started := time.Now()
	callCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint.URL, bytes.NewReader(body))
	if err != nil {
		monitorClientCall(role, endpoint.Name, "error", time.Since(started))
		return rpcResponse{}, errors.Wrap(err, "failed to create HTTP request")
	}
	httpReq.Header.Set("Content-Type", "application/json")

	authHeader, err := s.outboundAuthorizationHeader(endpoint, incomingAuth)
	if err != nil {
		monitorClientCall(role, endpoint.Name, "error", time.Since(started))
		return rpcResponse{}, err
	}
	if authHeader != "" {
		httpReq.Header.Set("Authorization", authHeader)
	}

	httpResp, err := s.httpClient.Do(httpReq)
	if err != nil {
		monitorClientCall(role, endpoint.Name, "error", time.Since(started))
		return rpcResponse{}, err
	}
	defer func() {
		_ = httpResp.Body.Close()
	}()

	respBytes, _, err := readDecompressedBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"), s.maxBodyBytes)
	if err != nil {
		monitorClientCall(role, endpoint.Name, "error", time.Since(started))
		return rpcResponse{}, errors.Wrap(err, "failed to read response body")
	}

	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		monitorClientCall(role, endpoint.Name, fmt.Sprintf("http_%d", httpResp.StatusCode), time.Since(started))
		snippet := strings.TrimSpace(string(respBytes))
		if len(snippet) > 256 {
			snippet = snippet[:256]
		}
		if snippet != "" {
			return rpcResponse{}, fmt.Errorf("unexpected HTTP status %d: %s", httpResp.StatusCode, snippet)
		}
		return rpcResponse{}, fmt.Errorf("unexpected HTTP status %d", httpResp.StatusCode)
	}

	var decoded rpcResponse
	if err := json.Unmarshal(respBytes, &decoded); err != nil {
		monitorClientCall(role, endpoint.Name, "invalid_json", time.Since(started))
		return rpcResponse{}, errors.Wrap(err, "invalid JSON-RPC response")
	}

	outcome := "succeeded"
	if decoded.Error != nil {
		outcome = "rpc_error"
	}
	monitorClientCall(role, endpoint.Name, outcome, time.Since(started))

	return decoded, nil
}

func (s *Service) outboundAuthorizationHeader(endpoint *executionproxy.EndpointConfig, incomingAuth string) (string, error) {
	secret := endpoint.JWTSecret
	if len(secret) == 0 {
		secret = s.defaultJWTSecret
	}
	if len(secret) > 0 {
		token, err := signJWT(secret, time.Now())
		if err != nil {
			return "", errors.Wrap(err, "failed to sign outbound JWT")
		}
		return "Bearer " + token, nil
	}

	return incomingAuth, nil
}

func readDecompressedBody(body io.Reader, contentEncoding string, maxBytes int64) ([]byte, int, error) {
	reader := body
	if strings.EqualFold(strings.TrimSpace(contentEncoding), "gzip") {
		gzReader, err := gzip.NewReader(body)
		if err != nil {
			return nil, http.StatusBadRequest, errors.Wrap(err, "invalid gzip body")
		}
		defer func() {
			_ = gzReader.Close()
		}()
		reader = gzReader
	}

	limited := io.LimitReader(reader, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if int64(len(data)) > maxBytes {
		return nil, http.StatusRequestEntityTooLarge, errors.New("JSON-RPC body exceeds maximum size")
	}

	return data, http.StatusOK, nil
}

func isJSONNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || slices.Equal(trimmed, []byte("null"))
}

func effectiveID(id json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(id)) == 0 {
		return json.RawMessage("null")
	}

	return id
}

func makeErrorResponse(id json.RawMessage, code int, message string) rpcResponse {
	return rpcResponse{
		JSONRPC: jsonRPCVersion,
		ID:      effectiveID(id),
		Error: &rpcError{
			Code:    code,
			Message: message,
		},
	}
}

func makePayloadStatusResponse(id json.RawMessage, status string, latestValidHash json.RawMessage, validationError *string) rpcResponse {
	if len(latestValidHash) == 0 {
		latestValidHash = json.RawMessage("null")
	}
	resultBytes, _ := json.Marshal(payloadStatusResponse{
		Status:          status,
		LatestValidHash: latestValidHash,
		ValidationError: validationError,
	})

	return rpcResponse{
		JSONRPC: jsonRPCVersion,
		ID:      effectiveID(id),
		Result:  resultBytes,
	}
}

func makeForkchoiceResponse(id json.RawMessage, status string, latestValidHash json.RawMessage, validationError *string) rpcResponse {
	if len(latestValidHash) == 0 {
		latestValidHash = json.RawMessage("null")
	}
	resultBytes, _ := json.Marshal(forkchoiceUpdatedResponse{
		PayloadStatus: payloadStatusResponse{
			Status:          status,
			LatestValidHash: latestValidHash,
			ValidationError: validationError,
		},
		PayloadID: json.RawMessage("null"),
	})

	return rpcResponse{
		JSONRPC: jsonRPCVersion,
		ID:      effectiveID(id),
		Result:  resultBytes,
	}
}

func writeJSONResponse(w http.ResponseWriter, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
