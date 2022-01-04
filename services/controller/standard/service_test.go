// Copyright © 2020, 2021 Attestant Limited.
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
	"context"
	"testing"
	"time"

	"github.com/attestantio/vouch/mock"
	mockaccountmanager "github.com/attestantio/vouch/services/accountmanager/mock"
	mockattestationaggregator "github.com/attestantio/vouch/services/attestationaggregator/mock"
	mockattester "github.com/attestantio/vouch/services/attester/mock"
	mockbeaconblockproposer "github.com/attestantio/vouch/services/beaconblockproposer/mock"
	mockbeaconcommitteesubscriber "github.com/attestantio/vouch/services/beaconcommitteesubscriber/mock"
	standardchaintime "github.com/attestantio/vouch/services/chaintime/standard"
	"github.com/attestantio/vouch/services/controller/standard"
	nullmetrics "github.com/attestantio/vouch/services/metrics/null"
	mockscheduler "github.com/attestantio/vouch/services/scheduler/mock"
	mocksynccommitteeaggregator "github.com/attestantio/vouch/services/synccommitteeaggregator/mock"
	mocksynccommitteemessenger "github.com/attestantio/vouch/services/synccommitteemessenger/mock"
	mocksynccommitteesubscriber "github.com/attestantio/vouch/services/synccommitteesubscriber/mock"
	"github.com/attestantio/vouch/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	ctx := context.Background()

	zerolog.SetGlobalLevel(zerolog.Disabled)

	genesisTime := time.Now()
	slotDuration := 12 * time.Second
	slotsPerEpoch := uint64(32)
	genesisTimeProvider := mock.NewGenesisTimeProvider(genesisTime)
	slotDurationProvider := mock.NewSlotDurationProvider(slotDuration)
	slotsPerEpochProvider := mock.NewSlotsPerEpochProvider(slotsPerEpoch)
	specProvider := mock.NewSpecProvider()
	forkScheduleProvider := mock.NewForkScheduleProvider()

	mockBlockHeadersProvider := mock.NewBeaconBlockHeadersProvider()
	mockSignedBeaconBlockProvider := mock.NewSignedBeaconBlockProvider()
	mockSyncCommitteeAggregator := mocksynccommitteeaggregator.New()
	proposerDutiesProvider := mock.NewProposerDutiesProvider()
	attesterDutiesProvider := mock.NewAttesterDutiesProvider()
	syncCommitteeDutiesProvider := mock.NewSyncCommitteeDutiesProvider()
	mockScheduler := mockscheduler.New()
	mockAttester := mockattester.New()
	mockSyncCommitteeMessenger := mocksynccommitteemessenger.New()
	mockSyncCommitteeSubscriber := mocksynccommitteesubscriber.New()
	mockAttestationAggregator := mockattestationaggregator.New()
	mockValidatingAccountsProvider := mockaccountmanager.NewValidatingAccountsProvider()
	mockAccountsRefresher := mockaccountmanager.NewRefresher()
	mockBeaconBlockProposer := mockbeaconblockproposer.New()
	mockEventsProvider := mock.NewEventsProvider()
	mockBeaconCommitteeSubscriber := mockbeaconcommitteesubscriber.New()

	chainTime, err := standardchaintime.New(ctx,
		standardchaintime.WithGenesisTimeProvider(genesisTimeProvider),
		standardchaintime.WithSlotDurationProvider(slotDurationProvider),
		standardchaintime.WithSlotsPerEpochProvider(slotsPerEpochProvider),
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		params   []standard.Parameter
		err      string
		logEntry string
	}{
		{
			name: "MonitorNil",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: no monitor specified",
		},
		{
			name: "SpecProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: no spec provider specified",
		},
		{
			name: "ForkScheduleProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithSpecProvider(specProvider),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: no fork schedule provider specified",
		},
		{
			name: "SpecProviderErrors",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(mock.NewErroringSpecProvider()),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: failed to obtain spec: error",
		},
		{
			name: "ChainTimeServiceMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: no chain time service specified",
		},
		{
			name: "ProposerDutiesProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: no proposer duties provider specified",
		},
		{
			name: "AttesterDutiesProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: no attester duties provider specified",
		},
		{
			name: "EventsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: no events provider specified",
		},
		{
			name: "ValidatingAccountsProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: no validating accounts provider specified",
		},
		{
			name: "SchedulerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: no scheduler service specified",
		},
		{
			name: "AttesterMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: no attester specified",
		},
		{
			name: "BeaconBlockProposerMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: no beacon block proposer specified",
		},
		{
			name: "BeaconCommitteeSubscriberMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: no beacon committee subscriber specified",
		},
		{
			name: "AttestationAggregatorMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: no attestation aggregator specified",
		},
		{
			name: "AccountsRefresherMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
			},
			err: "problem with parameters: no accounts refresher specified",
		},
		{
			name: "BeaconBlockHeadersProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
				standard.WithReorgs(false),
			},
			err: "problem with parameters: no beacon block headers provider specified",
		},
		{
			name: "SignedBeaconBlockProviderMissing",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
				standard.WithReorgs(false),
			},
			err: "problem with parameters: no signed beacon block provider specified",
		},
		{
			name: "Good",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithMaxAttestationDelay(4 * time.Second),
				standard.WithMaxProposalDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithMaxSyncCommitteeMessageDelay(4 * time.Second),
				standard.WithAttestationAggregationDelay(8 * time.Second),
				standard.WithSyncCommitteeAggregationDelay(8 * time.Second),
				standard.WithReorgs(false),
			},
		},
		{
			name: "GoodDefaultDelays",
			params: []standard.Parameter{
				standard.WithLogLevel(zerolog.Disabled),
				standard.WithMonitor(nullmetrics.New(ctx)),
				standard.WithSpecProvider(specProvider),
				standard.WithForkScheduleProvider(forkScheduleProvider),
				standard.WithChainTimeService(chainTime),
				standard.WithProposerDutiesProvider(proposerDutiesProvider),
				standard.WithAttesterDutiesProvider(attesterDutiesProvider),
				standard.WithSyncCommitteeDutiesProvider(syncCommitteeDutiesProvider),
				standard.WithEventsProvider(mockEventsProvider),
				standard.WithValidatingAccountsProvider(mockValidatingAccountsProvider),
				standard.WithScheduler(mockScheduler),
				standard.WithAttester(mockAttester),
				standard.WithSyncCommitteeMessenger(mockSyncCommitteeMessenger),
				standard.WithSyncCommitteeAggregator(mockSyncCommitteeAggregator),
				standard.WithSyncCommitteeSubscriber(mockSyncCommitteeSubscriber),
				standard.WithBeaconBlockProposer(mockBeaconBlockProposer),
				standard.WithBeaconCommitteeSubscriber(mockBeaconCommitteeSubscriber),
				standard.WithAttestationAggregator(mockAttestationAggregator),
				standard.WithAccountsRefresher(mockAccountsRefresher),
				standard.WithBeaconBlockHeadersProvider(mockBlockHeadersProvider),
				standard.WithSignedBeaconBlockProvider(mockSignedBeaconBlockProvider),
				standard.WithReorgs(true),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			_, err := standard.New(ctx, test.params...)
			if test.err != "" {
				require.EqualError(t, err, test.err)
				if test.logEntry != "" {
					capture.AssertHasEntry(t, test.logEntry)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
