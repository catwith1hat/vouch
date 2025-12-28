// Copyright © 2020 - 2025 Attestant Limited.
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
	"time"

	"github.com/attestantio/vouch/services/metrics"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	ethproofsCacheSize *prometheus.GaugeVec
	ethproofsQueryTotal *prometheus.CounterVec
	ethproofsAPILatency prometheus.Histogram
)

func registerMetrics(ctx context.Context, monitor metrics.Service) error {
	if monitor == nil {
		// No monitor.
		return nil
	}
	if monitor.Presenter() == "prometheus" {
		return registerPrometheusMetrics(ctx)
	}
	return nil
}

func registerPrometheusMetrics(_ context.Context) error {
	ethproofsCacheSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "vouch",
		Subsystem: "ethproofs_tracker",
		Name:      "cache_size",
		Help:      "Number of proven epochs in cache.",
	}, []string{})
	if err := prometheus.Register(ethproofsCacheSize); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			ethproofsCacheSize = alreadyRegisteredError.ExistingCollector.(*prometheus.GaugeVec)
		} else {
			return err
		}
	}

	ethproofsQueryTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vouch",
		Subsystem: "ethproofs_tracker",
		Name:      "query_total",
		Help:      "Total number of ethproofs API queries.",
	}, []string{"result"})
	if err := prometheus.Register(ethproofsQueryTotal); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			ethproofsQueryTotal = alreadyRegisteredError.ExistingCollector.(*prometheus.CounterVec)
		} else {
			return err
		}
	}

	ethproofsAPILatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "vouch",
		Subsystem: "ethproofs_tracker",
		Name:      "api_latency_seconds",
		Help:      "Latency of ethproofs API queries in seconds.",
		Buckets:   []float64{0.1, 0.5, 1.0, 2.0, 5.0},
	})
	if err := prometheus.Register(ethproofsAPILatency); err != nil {
		var alreadyRegisteredError prometheus.AlreadyRegisteredError
		if ok := errors.As(err, &alreadyRegisteredError); ok {
			ethproofsAPILatency = alreadyRegisteredError.ExistingCollector.(prometheus.Histogram)
		} else {
			return err
		}
	}

	return nil
}

func monitorEthproofsCacheSize(size int) {
	if ethproofsCacheSize != nil {
		ethproofsCacheSize.WithLabelValues().Set(float64(size))
	}
}

func monitorEthproofsQuery(proven bool) {
	if ethproofsQueryTotal != nil {
		result := "not_proven"
		if proven {
			result = "proven"
		}
		ethproofsQueryTotal.WithLabelValues(result).Inc()
	}
}

func monitorEthproofsAPILatency(started time.Time) {
	if ethproofsAPILatency != nil {
		ethproofsAPILatency.Observe(time.Since(started).Seconds())
	}
}
