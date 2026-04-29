package evm

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/vitwit/x402-go"
)

// Config is the single configuration struct for EVM network support.
// Pass it to New to create a Provider that satisfies x402.NetworkProvider.
type Config struct {
	// Networks lists the CAIP-2 network IDs this provider handles.
	// Defaults to DefaultNetworks() when nil.
	Networks []string

	// RPCEndpoints maps CAIP-2 network ID → Ethereum JSON-RPC URL.
	// Required for block queries and settlement.
	RPCEndpoints map[string]string

	// PrivateKeyHex is the 0x-prefixed hex private key of the facilitator wallet
	// used to sign and submit settlement transactions.
	// Optional: leave empty to create a verify-only provider.
	PrivateKeyHex string

	// TokenDomains maps lowercase token address → EIP-712 domain config.
	// Defaults to DefaultTokenDomains when nil.
	TokenDomains map[string]TokenDomainConfig

	// Logger is used for debug/info output. Defaults to a no-op if nil.
	Logger x402.Logger
}

// chainMeta holds static chain metadata for known EVM networks.
var chainMeta = map[string]x402.ChainInfo{
	NetworkBaseMainnet:    {Network: NetworkBaseMainnet, Name: "Base", Type: x402.ChainTypeEVM, NativeToken: "ETH", Decimals: 18},
	NetworkBaseSepolia:    {Network: NetworkBaseSepolia, Name: "Base Sepolia", Type: x402.ChainTypeEVM, NativeToken: "ETH", Decimals: 18},
	NetworkEthMainnet:     {Network: NetworkEthMainnet, Name: "Ethereum", Type: x402.ChainTypeEVM, NativeToken: "ETH", Decimals: 18},
	NetworkPolygonMainnet: {Network: NetworkPolygonMainnet, Name: "Polygon", Type: x402.ChainTypeEVM, NativeToken: "POL", Decimals: 18},
	NetworkPolygonAmoy:    {Network: NetworkPolygonAmoy, Name: "Polygon Amoy", Type: x402.ChainTypeEVM, NativeToken: "POL", Decimals: 18},
}

// Provider implements x402.NetworkProvider for EVM chains.
// It combines payment verification, settlement, and chain-info queries.
type Provider struct {
	networks []string
	cfg      Config
	verifier *Verifier
	settler  *Settler
	log      x402.Logger
}

// New creates a Provider from cfg.
// Returns an error only if a settler is requested (PrivateKeyHex set) and the
// ABI cannot be parsed — which should never happen in practice.
func New(cfg Config) (*Provider, error) {
	networks := cfg.Networks
	if networks == nil {
		networks = DefaultNetworks()
	}
	tokenDomains := cfg.TokenDomains
	if tokenDomains == nil {
		tokenDomains = DefaultTokenDomains
	}
	log := cfg.Logger
	if log == nil {
		log = x402.NopLogger{}
	}

	verifier := NewVerifier(networks, tokenDomains)
	verifier.rpcEndpoints = cfg.RPCEndpoints

	var settler *Settler
	if cfg.PrivateKeyHex != "" {
		var err error
		settler, err = NewSettler(networks, SettlerConfig{
			PrivateKeyHex: cfg.PrivateKeyHex,
			RPCEndpoints:  cfg.RPCEndpoints,
		})
		if err != nil {
			return nil, fmt.Errorf("create evm settler: %w", err)
		}
	}

	return &Provider{
		networks: networks,
		cfg:      cfg,
		verifier: verifier,
		settler:  settler,
		log:      log,
	}, nil
}

// --- x402.Verifier ---

func (p *Provider) Networks() []string     { return p.networks }
func (p *Provider) Schemes() []x402.Scheme { return p.verifier.Schemes() }

func (p *Provider) Verify(ctx context.Context, req x402.VerifyRequest) (x402.VerifyResult, error) {
	p.log.Debug("evm verify", "network", req.PaymentPayload.Accepted.Network, "scheme", req.PaymentPayload.Accepted.Scheme)
	return p.verifier.Verify(ctx, req)
}

// --- x402.Settler ---

func (p *Provider) Settle(ctx context.Context, req x402.SettleRequest) (x402.SettleResult, error) {
	if p.settler == nil {
		return x402.SettleResult{Error: "settler not configured (no private key)"}, nil
	}
	p.log.Debug("evm settle", "network", req.PaymentPayload.Accepted.Network)
	return p.settler.Settle(ctx, req)
}

// --- x402.ChainProvider ---

// ChainInfo returns static metadata for the given EVM network.
// For networks not in the built-in table, it derives info from the RPC.
func (p *Provider) ChainInfo(ctx context.Context, network string) (x402.ChainInfo, error) {
	if info, ok := chainMeta[network]; ok {
		return info, nil
	}
	// Unknown network: fetch chain ID from RPC and build a generic entry.
	rpcURL := p.cfg.RPCEndpoints[network]
	if rpcURL == "" {
		return x402.ChainInfo{}, fmt.Errorf("unknown network and no RPC endpoint: %s", network)
	}
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return x402.ChainInfo{}, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return x402.ChainInfo{}, fmt.Errorf("get chain id: %w", err)
	}
	return x402.ChainInfo{
		Network:     fmt.Sprintf("eip155:%s", chainID),
		Name:        fmt.Sprintf("EVM Chain %s", chainID),
		Type:        x402.ChainTypeEVM,
		NativeToken: "ETH",
		Decimals:    18,
	}, nil
}

// LatestBlock returns the latest block header for the given network.
func (p *Provider) LatestBlock(ctx context.Context, network string) (x402.BlockInfo, error) {
	return p.blockByNumber(ctx, network, nil)
}

// BlockByHeight returns the block at the given height.
func (p *Provider) BlockByHeight(ctx context.Context, network string, height int64) (x402.BlockInfo, error) {
	return p.blockByNumber(ctx, network, big.NewInt(height))
}

func (p *Provider) blockByNumber(ctx context.Context, network string, number *big.Int) (x402.BlockInfo, error) {
	rpcURL := p.cfg.RPCEndpoints[network]
	if rpcURL == "" {
		return x402.BlockInfo{}, fmt.Errorf("no RPC endpoint for %s", network)
	}
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return x402.BlockInfo{}, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	header, err := client.HeaderByNumber(ctx, number)
	if err != nil {
		return x402.BlockInfo{}, fmt.Errorf("get header: %w", err)
	}
	return x402.BlockInfo{
		Network:   network,
		Height:    header.Number.Int64(),
		Hash:      header.Hash().Hex(),
		Timestamp: time.Unix(int64(header.Time), 0).UTC(),
		TxCount:   -1, // header doesn't carry tx count; use BlockByNumber if needed
	}, nil
}

// AddNetwork registers a new EVM network at runtime.
// Useful for custom or not-yet-built-in chains.
func (p *Provider) AddNetwork(network string, rpcURL string, meta x402.ChainInfo) {
	p.networks = append(p.networks, network)
	if p.cfg.RPCEndpoints == nil {
		p.cfg.RPCEndpoints = make(map[string]string)
	}
	p.cfg.RPCEndpoints[network] = rpcURL
	chainMeta[network] = meta

	// Re-register the underlying verifier/settler for the new network
	p.verifier.networks = append(p.verifier.networks, network)
	if p.settler != nil {
		p.settler.networks = append(p.settler.networks, network)
		if p.settler.cfg.RPCEndpoints == nil {
			p.settler.cfg.RPCEndpoints = make(map[string]string)
		}
		p.settler.cfg.RPCEndpoints[network] = rpcURL
	}
	p.log.Info("added evm network", "network", network)
}

// AddTokenDomain registers EIP-712 domain config for a custom token.
// Call this for any ERC-20 that is not already in DefaultTokenDomains.
func (p *Provider) AddTokenDomain(tokenAddr string, cfg TokenDomainConfig) {
	p.verifier.tokenDomains[strings.ToLower(tokenAddr)] = cfg
	p.log.Info("added token domain", "token", tokenAddr)
}
