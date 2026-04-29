package x402

import "context"

// Logger is the minimal logging interface consumed by Server and providers.
// *log/slog.Logger satisfies this interface directly.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// NopLogger is a Logger that discards all output.
// Providers and applications use it as a default when no logger is configured.
type NopLogger struct{}

func (NopLogger) Debug(_ string, _ ...any) {}
func (NopLogger) Info(_ string, _ ...any)  {}
func (NopLogger) Warn(_ string, _ ...any)  {}
func (NopLogger) Error(_ string, _ ...any) {}

// Verifier checks that a payment payload satisfies a payment option without
// broadcasting anything on-chain.
type Verifier interface {
	Networks() []string
	Schemes() []Scheme
	Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error)
}

// Settler broadcasts a verified payment on-chain and returns the result.
type Settler interface {
	Networks() []string
	Schemes() []Scheme
	Settle(ctx context.Context, req SettleRequest) (SettleResult, error)
}

// ChainProvider exposes chain metadata and block queries for one or more networks.
type ChainProvider interface {
	// Networks returns the CAIP-2 identifiers this provider handles.
	Networks() []string
	// ChainInfo returns static metadata for a registered network.
	ChainInfo(ctx context.Context, network string) (ChainInfo, error)
	// LatestBlock returns the most recent block on the given network.
	LatestBlock(ctx context.Context, network string) (BlockInfo, error)
	// BlockByHeight returns the block at a specific height/slot/sequence.
	BlockByHeight(ctx context.Context, network string, height int64) (BlockInfo, error)
}

// NetworkProvider is the full interface that a single chain implementation can
// satisfy to register as verifier, settler, and chain-info provider in one call.
type NetworkProvider interface {
	Verifier
	Settler
	ChainProvider
}
