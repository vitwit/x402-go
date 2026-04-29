package x402

import (
	"context"
	"fmt"
	"sync"
)

// Registry holds all registered Verifiers, Settlers, and ChainProviders.
type Registry struct {
	verifiers map[string]Verifier      // key: network+":"+scheme
	settlers  map[string]Settler       // key: network+":"+scheme
	chains    map[string]ChainProvider // key: network
	caps      []SupportedCapability    // ordered list of registered (network, scheme) pairs
}

func NewRegistry() *Registry {
	return &Registry{
		verifiers: make(map[string]Verifier),
		settlers:  make(map[string]Settler),
		chains:    make(map[string]ChainProvider),
	}
}

func registryKey(network string, scheme Scheme) string {
	return network + ":" + string(scheme)
}

// RegisterVerifier registers v for every (network, scheme) pair it declares.
func (r *Registry) RegisterVerifier(v Verifier) {
	for _, network := range v.Networks() {
		for _, scheme := range v.Schemes() {
			key := registryKey(network, scheme)
			if _, exists := r.verifiers[key]; !exists {
				r.caps = append(r.caps, SupportedCapability{Network: network, Scheme: scheme})
			}
			r.verifiers[key] = v
		}
	}
}

// RegisterSettler registers s for every (network, scheme) pair it declares.
func (r *Registry) RegisterSettler(s Settler) {
	for _, network := range s.Networks() {
		for _, scheme := range s.Schemes() {
			r.settlers[registryKey(network, scheme)] = s
		}
	}
}

// RegisterChainProvider registers p for every network it declares.
func (r *Registry) RegisterChainProvider(p ChainProvider) {
	for _, network := range p.Networks() {
		r.chains[network] = p
	}
}

// RegisterNetworkProvider registers a combined verifier+settler+chain provider
// in a single call.
func (r *Registry) RegisterNetworkProvider(p NetworkProvider) {
	r.RegisterVerifier(p)
	r.RegisterSettler(p)
	r.RegisterChainProvider(p)
}

// Verify finds the matching Verifier and calls it.
func (r *Registry) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	key := registryKey(req.PaymentPayload.Accepted.Network, req.PaymentPayload.Accepted.Scheme)
	v, ok := r.verifiers[key]
	if !ok {
		return VerifyResult{}, fmt.Errorf("no verifier registered for %s", key)
	}
	return v.Verify(ctx, req)
}

// Settle finds the matching Settler and calls it.
func (r *Registry) Settle(ctx context.Context, req SettleRequest) (SettleResult, error) {
	key := registryKey(req.PaymentPayload.Accepted.Network, req.PaymentPayload.Accepted.Scheme)
	s, ok := r.settlers[key]
	if !ok {
		return SettleResult{}, fmt.Errorf("no settler registered for %s", key)
	}
	return s.Settle(ctx, req)
}

// ChainInfo returns static metadata for the given network.
func (r *Registry) ChainInfo(ctx context.Context, network string) (ChainInfo, error) {
	p, ok := r.chains[network]
	if !ok {
		return ChainInfo{}, fmt.Errorf("no chain provider registered for %s", network)
	}
	return p.ChainInfo(ctx, network)
}

// LatestBlock returns the most recent block on the given network.
func (r *Registry) LatestBlock(ctx context.Context, network string) (BlockInfo, error) {
	p, ok := r.chains[network]
	if !ok {
		return BlockInfo{}, fmt.Errorf("no chain provider registered for %s", network)
	}
	return p.LatestBlock(ctx, network)
}

// BlockByHeight returns the block at height on the given network.
func (r *Registry) BlockByHeight(ctx context.Context, network string, height int64) (BlockInfo, error) {
	p, ok := r.chains[network]
	if !ok {
		return BlockInfo{}, fmt.Errorf("no chain provider registered for %s", network)
	}
	return p.BlockByHeight(ctx, network, height)
}

// ListChains returns ChainInfo for every registered network.
// Errors from individual providers are silently skipped.
func (r *Registry) ListChains(ctx context.Context) []ChainInfo {
	var out []ChainInfo
	for network, p := range r.chains {
		if info, err := p.ChainInfo(ctx, network); err == nil {
			out = append(out, info)
		}
	}
	return out
}

// Supported returns all (network, scheme) pairs for which a verifier is registered,
// in registration order.
func (r *Registry) Supported() []SupportedCapability {
	out := make([]SupportedCapability, len(r.caps))
	copy(out, r.caps)
	return out
}

// IsNetworkSupported reports whether any verifier handles the given network.
func (r *Registry) IsNetworkSupported(network string) bool {
	for _, cap := range r.caps {
		if cap.Network == network {
			return true
		}
	}
	return false
}

// BatchSettle settles multiple payments concurrently and returns results in the
// same order as the input slice. Each settlement is independent — failure of one
// does not affect others.
func (r *Registry) BatchSettle(ctx context.Context, reqs []SettleRequest) []SettleResult {
	results := make([]SettleResult, len(reqs))
	var wg sync.WaitGroup
	for i, req := range reqs {
		wg.Add(1)
		go func(i int, req SettleRequest) {
			defer wg.Done()
			result, err := r.Settle(ctx, req)
			if err != nil {
				results[i] = SettleResult{Error: err.Error()}
				return
			}
			results[i] = result
		}(i, req)
	}
	wg.Wait()
	return results
}
