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
	"context"
	"errors"
	"time"

	"github.com/attestantio/vouch/services/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	proxyRequestsCounter      *prometheus.CounterVec
	proxyRequestDuration      *prometheus.HistogramVec
	proxyVerificationsCounter *prometheus.CounterVec
	proxyClientRequests       *prometheus.CounterVec
	proxyClientDuration       *prometheus.HistogramVec
)

func registerMetrics(_ context.Context, monitor metrics.Service) error {
	if monitor == nil || monitor.Presenter() != "prometheus" {
		return nil
	}

	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "executionproxy",
		Name:      "requests_total",
		Help:      "Total JSON-RPC requests handled by the execution proxy.",
	}, []string{"method", "outcome"})
	if err := registerCounterVec(&requests); err != nil {
		return err
	}
	proxyRequestsCounter = requests

	requestDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "executionproxy",
		Name:      "request_duration_seconds",
		Help:      "Time spent handling JSON-RPC requests in the execution proxy.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"method"})
	if err := registerHistogramVec(&requestDuration); err != nil {
		return err
	}
	proxyRequestDuration = requestDuration

	verifications := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "executionproxy",
		Name:      "verifications_total",
		Help:      "Total Pre-BAL payload verification outcomes across primary and secondary execution clients.",
	}, []string{"outcome"})
	if err := registerCounterVec(&verifications); err != nil {
		return err
	}
	proxyVerificationsCounter = verifications

	clientRequests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "executionproxy",
		Name:      "client_requests_total",
		Help:      "Total outbound JSON-RPC calls to primary and secondary execution clients.",
	}, []string{"role", "client", "outcome"})
	if err := registerCounterVec(&clientRequests); err != nil {
		return err
	}
	proxyClientRequests = clientRequests

	clientDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "executionproxy",
		Name:      "client_duration_seconds",
		Help:      "Latency of outbound JSON-RPC calls to primary and secondary execution clients.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"role", "client"})
	if err := registerHistogramVec(&clientDuration); err != nil {
		return err
	}
	proxyClientDuration = clientDuration

	return nil
}

func registerCounterVec(target **prometheus.CounterVec) error {
	if err := prometheus.Register(*target); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			*target = alreadyRegistered.ExistingCollector.(*prometheus.CounterVec)
			return nil
		}
		return err
	}

	return nil
}

func registerHistogramVec(target **prometheus.HistogramVec) error {
	if err := prometheus.Register(*target); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			*target = alreadyRegistered.ExistingCollector.(*prometheus.HistogramVec)
			return nil
		}
		return err
	}

	return nil
}

func monitorProxyRequest(method string, outcome string, duration time.Duration) {
	if proxyRequestsCounter != nil {
		proxyRequestsCounter.WithLabelValues(method, outcome).Inc()
	}
	if proxyRequestDuration != nil {
		proxyRequestDuration.WithLabelValues(method).Observe(duration.Seconds())
	}
}

func monitorVerification(outcome string) {
	if proxyVerificationsCounter != nil {
		proxyVerificationsCounter.WithLabelValues(outcome).Inc()
	}
}

func monitorClientCall(role string, client string, outcome string, duration time.Duration) {
	if proxyClientRequests != nil {
		proxyClientRequests.WithLabelValues(role, client, outcome).Inc()
	}
	if proxyClientDuration != nil {
		proxyClientDuration.WithLabelValues(role, client).Observe(duration.Seconds())
	}
}
