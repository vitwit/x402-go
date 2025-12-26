package metrics

import "time"

type Recorder interface {
	IncCounter(name string, labels map[string]string)
	ObserveLatency(name string, duration time.Duration, labels map[string]string)
}
