// Copyright © 2020 - 2023 Attestant Limited.
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
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/attestantio/vouch/services/accountmanager"
	"github.com/attestantio/vouch/services/attester"
	"github.com/attestantio/vouch/services/chaintime"
	"github.com/attestantio/vouch/services/metrics"
	"github.com/attestantio/vouch/services/signer"
	"github.com/attestantio/vouch/services/submitter"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// Service is a beacon block attester.
type Service struct {
	monitor                    metrics.AttestationMonitor
	processConcurrency         int64
	slotsPerEpoch              uint64
	chainTimeService           chaintime.Service
	validatingAccountsProvider accountmanager.ValidatingAccountsProvider
	attestationDataProvider    eth2client.AttestationDataProvider
	attestationsSubmitter      submitter.AttestationsSubmitter
	beaconAttestationsSigner   signer.BeaconAttestationsSigner
	attested                   map[phase0.Epoch]map[phase0.ValidatorIndex]struct{}
	attestedMu                 sync.Mutex
}

// module-wide log.
var log zerolog.Logger

// New creates a new beacon block attester.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "attester").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	specResponse, err := parameters.specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain spec")
	}
	spec := specResponse.Data

	tmp, exists := spec["SLOTS_PER_EPOCH"]
	if !exists {
		return nil, errors.New("SLOTS_PER_EPOCH not found in spec")
	}
	slotsPerEpoch, ok := tmp.(uint64)
	if !ok {
		return nil, errors.New("SLOTS_PER_EPOCH of unexpected type")
	}

	s := &Service{
		monitor:                    parameters.monitor,
		processConcurrency:         parameters.processConcurrency,
		slotsPerEpoch:              slotsPerEpoch,
		chainTimeService:           parameters.chainTimeService,
		validatingAccountsProvider: parameters.validatingAccountsProvider,
		attestationDataProvider:    parameters.attestationDataProvider,
		attestationsSubmitter:      parameters.attestationsSubmitter,
		beaconAttestationsSigner:   parameters.beaconAttestationsSigner,
		attested:                   make(map[phase0.Epoch]map[phase0.ValidatorIndex]struct{}),
	}
	log.Trace().Int64("process_concurrency", s.processConcurrency).Msg("Set process concurrency")

	return s, nil
}

// Attest carries out attestations for a slot.
// It returns a map of attestations made, keyed on the validator index.
func (s *Service) Attest(ctx context.Context, data interface{}) ([]*phase0.Attestation, error) {
	ctx, span := otel.Tracer("attestantio.vouch.services.attester.standard").Start(ctx, "Attest")
	defer span.End()
	started := time.Now()

	duty, ok := data.(*attester.Duty)
	if !ok {
		s.monitor.AttestationsCompleted(started, 0, len(duty.ValidatorIndices()), "failed")
		return nil, errors.New("passed invalid data structure")
	}
	span.SetAttributes(attribute.Int64("slot", int64(duty.Slot())))

	// Ensure that we have an attested map for this epoch.
	epoch := s.chainTimeService.SlotToEpoch(duty.Slot())
	s.attestedMu.Lock()
	if _, exists := s.attested[epoch]; !exists {
		s.attested[epoch] = make(map[phase0.ValidatorIndex]struct{})
	}
	s.attestedMu.Unlock()

	// Filter the list of validator indices.
	validatorIndices := make([]phase0.ValidatorIndex, 0, len(duty.ValidatorIndices()))
	uints := make([]uint64, 0, len(duty.ValidatorIndices()))
	for i, index := range duty.ValidatorIndices() {
		s.attestedMu.Lock()
		if _, exists := s.attested[epoch][index]; exists {
			log.Warn().Uint64("slot", uint64(duty.Slot())).Int("array_index", i).Uint64("validator_index", uint64(index)).Msg("Validator already attested this epoch; not attesting again")
		} else {
			validatorIndices = append(validatorIndices, index)
			uints = append(uints, uint64(index))
			s.attested[epoch][index] = struct{}{}
		}
		s.attestedMu.Unlock()
	}
	log := log.With().Uint64("slot", uint64(duty.Slot())).Uints64("validator_indices", uints).Logger()

	// Fetch the attestation data.
	attestationDataResponse, err := s.attestationDataProvider.AttestationData(ctx, &api.AttestationDataOpts{
		Slot:           duty.Slot(),
		CommitteeIndex: duty.CommitteeIndices()[0],
	})
	if err != nil {
		s.monitor.AttestationsCompleted(started, duty.Slot(), len(validatorIndices), "failed")
		return nil, errors.Wrap(err, "failed to obtain attestation data")
	}
	attestationData := attestationDataResponse.Data
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Obtained attestation data")

	if attestationData.Slot != duty.Slot() {
		s.monitor.AttestationsCompleted(started, duty.Slot(), len(validatorIndices), "failed")
		return nil, fmt.Errorf("attestation request for slot %d returned data for slot %d", duty.Slot(), attestationData.Slot)
	}
	if attestationData.Source.Epoch > attestationData.Target.Epoch {
		s.monitor.AttestationsCompleted(started, duty.Slot(), len(validatorIndices), "failed")
		return nil, fmt.Errorf("attestation request for slot %d returned source epoch %d greater than target epoch %d", duty.Slot(), attestationData.Source.Epoch, attestationData.Target.Epoch)
	}
	if attestationData.Target.Epoch > phase0.Epoch(uint64(duty.Slot())/s.slotsPerEpoch) {
		s.monitor.AttestationsCompleted(started, duty.Slot(), len(validatorIndices), "failed")
		return nil, fmt.Errorf("attestation request for slot %d returned target epoch %d greater than current epoch %d", duty.Slot(), attestationData.Target.Epoch, phase0.Epoch(uint64(duty.Slot())/s.slotsPerEpoch))
	}

	// Fetch the validating accounts.
	validatingAccounts, err := s.validatingAccountsProvider.ValidatingAccountsForEpochByIndex(ctx, phase0.Epoch(uint64(duty.Slot())/s.slotsPerEpoch), validatorIndices)
	if err != nil {
		s.monitor.AttestationsCompleted(started, duty.Slot(), len(validatorIndices), "failed")
		return nil, errors.Wrap(err, "failed to obtain attesting validator accounts")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Int("validating_accounts", len(validatingAccounts)).Msg("Obtained validating accounts")

	// Break the map in to two arrays.
	accountValidatorIndices := make([]phase0.ValidatorIndex, 0, len(validatingAccounts))
	accountsArray := make([]e2wtypes.Account, 0, len(validatingAccounts))
	for index, account := range validatingAccounts {
		accountValidatorIndices = append(accountValidatorIndices, index)
		accountsArray = append(accountsArray, account)
	}

	// Set the per-validator information.
	validatorIndexToArrayIndexMap := make(map[phase0.ValidatorIndex]int)
	for i, index := range validatorIndices {
		validatorIndexToArrayIndexMap[index] = i
	}
	committeeIndices := make([]phase0.CommitteeIndex, len(validatingAccounts))
	validatorCommitteeIndices := make([]phase0.ValidatorIndex, len(validatingAccounts))
	committeeSizes := make([]uint64, len(validatingAccounts))
	for i := range accountsArray {
		committeeIndices[i] = duty.CommitteeIndices()[validatorIndexToArrayIndexMap[accountValidatorIndices[i]]]
		validatorCommitteeIndices[i] = phase0.ValidatorIndex(duty.ValidatorCommitteeIndices()[validatorIndexToArrayIndexMap[accountValidatorIndices[i]]])
		committeeSizes[i] = duty.CommitteeSize(committeeIndices[i])
	}

	attestations, err := s.attest(ctx,
		duty,
		accountsArray,
		committeeIndices,
		validatorCommitteeIndices,
		committeeSizes,
		attestationData,
		started,
	)
	if err != nil {
		s.monitor.AttestationsCompleted(started, duty.Slot(), len(validatorIndices), "failed")
		return nil, err
	}

	if len(attestations) < len(validatorIndices) {
		log.Error().Stringer("duty", duty).Int("total_attestations", len(validatorIndices)).Int("failed_attestations", len(validatorIndices)-len(attestations)).Msg("Some attestations failed")
		s.monitor.AttestationsCompleted(started, duty.Slot(), len(validatorIndices)-len(attestations), "failed")
	}
	s.monitor.AttestationsCompleted(started, duty.Slot(), len(attestations), "succeeded")

	// Housekeep attested map.
	if epoch > 1 {
		s.attestedMu.Lock()
		delete(s.attested, epoch-2)
		s.attestedMu.Unlock()
	}

	return attestations, nil
}

// attest carries out the internal work of attesting.
// skipcq: RVV-B0001
func (s *Service) attest(
	ctx context.Context,
	duty *attester.Duty,
	accounts []e2wtypes.Account,
	committeeIndices []phase0.CommitteeIndex,
	validatorCommitteeIndices []phase0.ValidatorIndex,
	committeeSizes []uint64,
	data *phase0.AttestationData,
	started time.Time,
) ([]*phase0.Attestation, error) {
	// Sign the attestation for all validating accounts.
	uintCommitteeIndices := make([]uint64, len(committeeIndices))
	for i := range committeeIndices {
		uintCommitteeIndices[i] = uint64(committeeIndices[i])
	}
	accountsArray := make([]e2wtypes.Account, 0, len(accounts))
	accountsArray = append(accountsArray, accounts...)

	sigs, err := s.beaconAttestationsSigner.SignBeaconAttestations(ctx,
		accountsArray,
		duty.Slot(),
		committeeIndices,
		data.BeaconBlockRoot,
		data.Source.Epoch,
		data.Source.Root,
		data.Target.Epoch,
		data.Target.Root,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign beacon attestations")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Signed")

	// Create the attestations.
	zeroSig := phase0.BLSSignature{}
	attestations := make([]*phase0.Attestation, 0, len(sigs))
	for i := range sigs {
		if bytes.Equal(sigs[i][:], zeroSig[:]) {
			log.Warn().Msg("No signature for validator; not creating attestation")
			continue
		}
		aggregationBits := bitfield.NewBitlist(committeeSizes[i])
		aggregationBits.SetBitAt(uint64(validatorCommitteeIndices[i]), true)
		attestation := &phase0.Attestation{
			AggregationBits: aggregationBits,
			Data: &phase0.AttestationData{
				Slot:            duty.Slot(),
				Index:           committeeIndices[i],
				BeaconBlockRoot: data.BeaconBlockRoot,
				Source: &phase0.Checkpoint{
					Epoch: data.Source.Epoch,
					Root:  data.Source.Root,
				},
				Target: &phase0.Checkpoint{
					Epoch: data.Target.Epoch,
					Root:  data.Target.Root,
				},
			},
		}
		copy(attestation.Signature[:], sigs[i][:])
		attestations = append(attestations, attestation)
	}

	if len(attestations) == 0 {
		log.Info().Msg("No signed attestations; not submitting")
		return attestations, nil
	}

	// Submit the attestations.
	submissionStarted := time.Now()
	if err := s.attestationsSubmitter.SubmitAttestations(ctx, attestations); err != nil {
		return nil, errors.Wrap(err, "failed to submit attestations")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Dur("submission_elapsed", time.Since(submissionStarted)).Msg("Submitted attestations")

	return attestations, nil
}
