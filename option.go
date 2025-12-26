package x402

import (
	"time"

	"github.com/vitwit/x402/logger"
	"github.com/vitwit/x402/metrics"
)

type Option func(*X402)

func WithLogger(l logger.Logger) Option {
	return func(x *X402) {
		x.logger = l
	}
}

func WithMetrics(r metrics.Recorder) Option {
	return func(x *X402) {
		x.metrics = r
	}
}

func WithTimeout(t time.Duration) Option {
	return func(x *X402) {
		x.timeout = t
	}
}
