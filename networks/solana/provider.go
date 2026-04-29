package solana

import (
	"context"
	"fmt"
	"time"

	solanago "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/vitwit/x402-go"
)

// Config is the single configuration struct for Solana network support.
type Config struct {
	// Networks lists CAIP-2 network IDs. Defaults to DefaultNetworks().
	Networks []string

	// RPCEndpoints maps CAIP-2 network ID → Solana JSON-RPC HTTP URL.
	RPCEndpoints map[string]string

	// WSEndpoints maps CAIP-2 network ID → Solana JSON-RPC WebSocket URL.
	// Used for confirmed-transaction delivery during settlement.
	WSEndpoints map[string]string

	// PrivateKey is the facilitator's Solana private key.
	// Required for settlement; leave zero-value for verify-only.
	PrivateKey solanago.PrivateKey

	// Logger defaults to a no-op when nil.
	Logger x402.Logger
}

var chainMeta = map[string]x402.ChainInfo{
	NetworkMainnet: {Network: NetworkMainnet, Name: "Solana", Type: x402.ChainTypeSolana, NativeToken: "SOL", Decimals: 9},
	NetworkDevnet:  {Network: NetworkDevnet, Name: "Solana Devnet", Type: x402.ChainTypeSolana, NativeToken: "SOL", Decimals: 9},
	NetworkTestnet: {Network: NetworkTestnet, Name: "Solana Testnet", Type: x402.ChainTypeSolana, NativeToken: "SOL", Decimals: 9},
}

// Provider implements x402.NetworkProvider for Solana.
type Provider struct {
	networks []string
	cfg      Config
	verifier *Verifier
	settler  *Settler
	log      x402.Logger
}

// New creates a Provider from cfg.
func New(cfg Config) *Provider {
	networks := cfg.Networks
	if networks == nil {
		networks = DefaultNetworks()
	}
	log := cfg.Logger
	if log == nil {
		log = x402.NopLogger{}
	}

	rpcEndpoints := cfg.RPCEndpoints
	if rpcEndpoints == nil {
		rpcEndpoints = make(map[string]string)
	}

	verifier := NewVerifier(networks, rpcEndpoints)
	settler := NewSettler(networks, SettlerConfig{
		PrivateKey:   cfg.PrivateKey,
		RPCEndpoints: rpcEndpoints,
		WSEndpoints:  cfg.WSEndpoints,
	})

	return &Provider{
		networks: networks,
		cfg:      cfg,
		verifier: verifier,
		settler:  settler,
		log:      log,
	}
}

// --- x402.Verifier ---

func (p *Provider) Networks() []string     { return p.networks }
func (p *Provider) Schemes() []x402.Scheme { return p.verifier.Schemes() }

func (p *Provider) Verify(ctx context.Context, req x402.VerifyRequest) (x402.VerifyResult, error) {
	p.log.Debug("solana verify", "network", req.PaymentPayload.Accepted.Network)
	return p.verifier.Verify(ctx, req)
}

// --- x402.Settler ---

func (p *Provider) Settle(ctx context.Context, req x402.SettleRequest) (x402.SettleResult, error) {
	if len(p.cfg.PrivateKey) == 0 {
		return x402.SettleResult{Error: "settler not configured (no private key)"}, nil
	}
	p.log.Debug("solana settle", "network", req.PaymentPayload.Accepted.Network)
	return p.settler.Settle(ctx, req)
}

// --- x402.ChainProvider ---

func (p *Provider) ChainInfo(_ context.Context, network string) (x402.ChainInfo, error) {
	if info, ok := chainMeta[network]; ok {
		return info, nil
	}
	return x402.ChainInfo{}, fmt.Errorf("unknown solana network: %s", network)
}

// LatestBlock returns the slot and block info for the most recently finalized slot.
func (p *Provider) LatestBlock(ctx context.Context, network string) (x402.BlockInfo, error) {
	client := p.rpcClient(network)
	if client == nil {
		return x402.BlockInfo{}, fmt.Errorf("no RPC endpoint for %s", network)
	}

	slot, err := client.GetSlot(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return x402.BlockInfo{}, fmt.Errorf("get slot: %w", err)
	}
	return p.blockBySlot(ctx, network, client, slot)
}

// BlockByHeight returns the block at the given slot number.
func (p *Provider) BlockByHeight(ctx context.Context, network string, height int64) (x402.BlockInfo, error) {
	client := p.rpcClient(network)
	if client == nil {
		return x402.BlockInfo{}, fmt.Errorf("no RPC endpoint for %s", network)
	}
	return p.blockBySlot(ctx, network, client, uint64(height))
}

func (p *Provider) blockBySlot(ctx context.Context, network string, client *rpc.Client, slot uint64) (x402.BlockInfo, error) {
	maxTxVersion := uint64(0)
	block, err := client.GetBlockWithOpts(ctx, slot, &rpc.GetBlockOpts{
		MaxSupportedTransactionVersion: &maxTxVersion,
		TransactionDetails:             "none",
		Rewards:                        func(b bool) *bool { return &b }(false),
	})
	if err != nil {
		return x402.BlockInfo{}, fmt.Errorf("get block: %w", err)
	}

	ts := time.Time{}
	if block.BlockTime != nil {
		ts = block.BlockTime.Time()
	}

	hash := ""
	if block.Blockhash != (solanago.Hash{}) {
		hash = block.Blockhash.String()
	}

	return x402.BlockInfo{
		Network:   network,
		Height:    int64(slot),
		Hash:      hash,
		Timestamp: ts.UTC(),
		TxCount:   -1,
	}, nil
}

// AddNetwork registers a new Solana-compatible network at runtime.
func (p *Provider) AddNetwork(network string, rpcURL string, wsURL string, meta x402.ChainInfo) {
	p.networks = append(p.networks, network)
	chainMeta[network] = meta
	if p.cfg.RPCEndpoints == nil {
		p.cfg.RPCEndpoints = make(map[string]string)
	}
	p.cfg.RPCEndpoints[network] = rpcURL
	if wsURL != "" {
		if p.cfg.WSEndpoints == nil {
			p.cfg.WSEndpoints = make(map[string]string)
		}
		p.cfg.WSEndpoints[network] = wsURL
	}
	// Propagate to inner verifier / settler
	p.verifier.networks = append(p.verifier.networks, network)
	p.verifier.rpcEndpoints[network] = rpcURL
	p.settler.networks = append(p.settler.networks, network)
	p.settler.cfg.RPCEndpoints[network] = rpcURL
	p.log.Info("added solana network", "network", network)
}

func (p *Provider) rpcClient(network string) *rpc.Client {
	url := p.cfg.RPCEndpoints[network]
	if url == "" {
		url = RPCFromNetwork(network)
	}
	if url == "" {
		return nil
	}
	return rpc.New(url)
}
