package metrics

import "time"

type NoopRecorder struct{}

func (NoopRecorder) IncCounter(string, map[string]string)                    {}
func (NoopRecorder) ObserveLatency(string, time.Duration, map[string]string) {}
