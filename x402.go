package x402

import (
	"context"
	"log/slog"
	"net/http"
)

// Config holds dependencies for an X402 instance.
type Config struct {
	// Logger is used for all internal log output.
	// Defaults to slog.Default() if nil.
	Logger Logger
}

// X402 is the top-level entry point for the x402 library.
// Facilitators create one, register network providers, then call Verify and Settle directly
// or embed payment enforcement in HTTP routes via Handler.
type X402 struct {
	registry *Registry
	log      Logger
}

// New creates a new X402 instance.
func New(cfg Config) *X402 {
	l := cfg.Logger
	if l == nil {
		l = slog.Default()
	}
	return &X402{registry: NewRegistry(), log: l}
}

// RegisterVerifier adds v to the instance. Returns X402 for chaining.
func (x *X402) RegisterVerifier(v Verifier) *X402 {
	x.registry.RegisterVerifier(v)
	x.log.Debug("registered verifier", "networks", v.Networks(), "schemes", v.Schemes())
	return x
}

// RegisterSettler adds st to the instance. Returns X402 for chaining.
func (x *X402) RegisterSettler(st Settler) *X402 {
	x.registry.RegisterSettler(st)
	x.log.Debug("registered settler", "networks", st.Networks(), "schemes", st.Schemes())
	return x
}

// RegisterChain adds a ChainProvider to the instance. Returns X402 for chaining.
func (x *X402) RegisterChain(p ChainProvider) *X402 {
	x.registry.RegisterChainProvider(p)
	x.log.Debug("registered chain provider", "networks", p.Networks())
	return x
}

// RegisterNetworkProvider registers a combined verifier + settler + chain provider
// in a single call. Returns X402 for chaining.
func (x *X402) RegisterNetworkProvider(p NetworkProvider) *X402 {
	x.registry.RegisterNetworkProvider(p)
	x.log.Info("registered network provider", "networks", p.Networks())
	return x
}

// Verify verifies a payment against the registered verifiers.
func (x *X402) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	return x.registry.Verify(ctx, req)
}

// Settle settles a verified payment via the registered settlers.
func (x *X402) Settle(ctx context.Context, req SettleRequest) (SettleResult, error) {
	return x.registry.Settle(ctx, req)
}

// BatchSettle settles multiple payments concurrently and returns results in the
// same order as the input slice. Each settlement is independent.
func (x *X402) BatchSettle(ctx context.Context, reqs []SettleRequest) []SettleResult {
	return x.registry.BatchSettle(ctx, reqs)
}

// Supported returns all (network, scheme) pairs the instance can handle.
func (x *X402) Supported() []SupportedCapability {
	return x.registry.Supported()
}

// IsNetworkSupported reports whether any registered verifier handles the given network.
func (x *X402) IsNetworkSupported(network string) bool {
	return x.registry.IsNetworkSupported(network)
}

// Handler wraps h with x402 payment enforcement.
// cfg.Registry is set automatically; callers should not set it.
func (x *X402) Handler(cfg HandlerConfig, h http.Handler) http.Handler {
	cfg.Registry = x.registry
	return PaymentMiddleware(cfg, h)
}

// Registry returns the underlying Registry for advanced use.
func (x *X402) Registry() *Registry { return x.registry }

// ChainInfo returns static metadata for the given CAIP-2 network.
func (x *X402) ChainInfo(ctx context.Context, network string) (ChainInfo, error) {
	return x.registry.ChainInfo(ctx, network)
}

// LatestBlock returns the most recent block on the given network.
func (x *X402) LatestBlock(ctx context.Context, network string) (BlockInfo, error) {
	return x.registry.LatestBlock(ctx, network)
}

// BlockByHeight returns the block at height on the given network.
func (x *X402) BlockByHeight(ctx context.Context, network string, height int64) (BlockInfo, error) {
	return x.registry.BlockByHeight(ctx, network, height)
}

// ListChains returns ChainInfo for every registered network.
func (x *X402) ListChains(ctx context.Context) []ChainInfo {
	return x.registry.ListChains(ctx)
}
