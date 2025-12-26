package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type PrometheusRecorder struct {
	counters  *prometheus.CounterVec
	histogram *prometheus.HistogramVec
}

func NewPrometheusRecorder() Recorder {
	counters := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "x402",
			Name:      "events_total",
			Help:      "x402 event counters",
		},
		[]string{"type", "network"},
	)

	histogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "x402",
			Name:      "latency_seconds",
			Help:      "x402 operation latency",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"operation", "network"},
	)

	prometheus.MustRegister(counters, histogram)

	return &PrometheusRecorder{
		counters:  counters,
		histogram: histogram,
	}
}

func (p *PrometheusRecorder) IncCounter(name string, labels map[string]string) {
	p.counters.With(prometheus.Labels{
		"type":    name,
		"network": labels["network"],
	}).Inc()
}

func (p *PrometheusRecorder) ObserveLatency(name string, d time.Duration, labels map[string]string) {
	p.histogram.With(prometheus.Labels{
		"operation": name,
		"network":   labels["network"],
	}).Observe(d.Seconds())
}
