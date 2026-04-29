package cosmos

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vitwit/x402-go"
)

// Config is the single configuration struct for Cosmos network support.
type Config struct {
	// Networks lists CAIP-2 network IDs. Defaults to DefaultNetworks().
	Networks []string

	// GRPCEndpoints maps CAIP-2 network ID → Cosmos gRPC address (host:port).
	// Used for tx simulation (verify) and broadcast (settle).
	GRPCEndpoints map[string]string

	// RESTEndpoints maps CAIP-2 network ID → Cosmos REST API base URL.
	// Used for block queries.
	RESTEndpoints map[string]string

	// Logger defaults to a no-op when nil.
	Logger x402.Logger
}

var chainMeta = map[string]x402.ChainInfo{
	NetworkCosmosHub: {Network: NetworkCosmosHub, Name: "Cosmos Hub", Type: x402.ChainTypeCosmos, NativeToken: "ATOM", Decimals: 6},
	NetworkOsmosis:   {Network: NetworkOsmosis, Name: "Osmosis", Type: x402.ChainTypeCosmos, NativeToken: "OSMO", Decimals: 6},
	NetworkNeutron:   {Network: NetworkNeutron, Name: "Neutron", Type: x402.ChainTypeCosmos, NativeToken: "NTRN", Decimals: 6},
	NetworkCelestia:  {Network: NetworkCelestia, Name: "Celestia", Type: x402.ChainTypeCosmos, NativeToken: "TIA", Decimals: 6},
}

// Provider implements x402.NetworkProvider for Cosmos SDK chains.
type Provider struct {
	networks []string
	cfg      Config
	verifier *Verifier
	settler  *Settler
	log      x402.Logger
	http     *http.Client
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

	grpcEndpoints := cfg.GRPCEndpoints
	if grpcEndpoints == nil {
		grpcEndpoints = make(map[string]string)
	}
	restEndpoints := cfg.RESTEndpoints
	if restEndpoints == nil {
		restEndpoints = make(map[string]string)
	}

	verifier := NewVerifier(networks)
	verifier.grpcURLs = grpcEndpoints

	settler := NewSettler(networks, SettlerConfig{
		GRPCEndpoints: grpcEndpoints,
		RESTEndpoints: restEndpoints,
	})

	return &Provider{
		networks: networks,
		cfg:      cfg,
		verifier: verifier,
		settler:  settler,
		log:      log,
		http:     &http.Client{},
	}
}

// --- x402.Verifier ---

func (p *Provider) Networks() []string     { return p.networks }
func (p *Provider) Schemes() []x402.Scheme { return p.verifier.Schemes() }

func (p *Provider) Verify(ctx context.Context, req x402.VerifyRequest) (x402.VerifyResult, error) {
	p.log.Debug("cosmos verify", "network", req.PaymentPayload.Accepted.Network)
	return p.verifier.Verify(ctx, req)
}

// --- x402.Settler ---

func (p *Provider) Settle(ctx context.Context, req x402.SettleRequest) (x402.SettleResult, error) {
	p.log.Debug("cosmos settle", "network", req.PaymentPayload.Accepted.Network)
	return p.settler.Settle(ctx, req)
}

// --- x402.ChainProvider ---

func (p *Provider) ChainInfo(_ context.Context, network string) (x402.ChainInfo, error) {
	if info, ok := chainMeta[network]; ok {
		return info, nil
	}
	return x402.ChainInfo{}, fmt.Errorf("unknown cosmos network: %s", network)
}

// LatestBlock fetches the most recent block via the Tendermint RPC endpoint.
// Falls back to Cosmos REST if no Tendermint RPC is configured.
func (p *Provider) LatestBlock(ctx context.Context, network string) (x402.BlockInfo, error) {
	if restURL := p.restURL(network); restURL != "" {
		return p.fetchBlock(ctx, network, restURL+"/cosmos/base/tendermint/v1beta1/blocks/latest")
	}
	return x402.BlockInfo{}, fmt.Errorf("no REST endpoint for %s", network)
}

// BlockByHeight fetches the block at height via the Cosmos REST API.
func (p *Provider) BlockByHeight(ctx context.Context, network string, height int64) (x402.BlockInfo, error) {
	restURL := p.restURL(network)
	if restURL == "" {
		return x402.BlockInfo{}, fmt.Errorf("no REST endpoint for %s", network)
	}
	return p.fetchBlock(ctx, network, fmt.Sprintf("%s/cosmos/base/tendermint/v1beta1/blocks/%d", restURL, height))
}

// AddNetwork registers a new Cosmos-compatible chain at runtime.
func (p *Provider) AddNetwork(network string, grpcURL string, restURL string, meta x402.ChainInfo) {
	p.networks = append(p.networks, network)
	chainMeta[network] = meta
	if p.cfg.GRPCEndpoints == nil {
		p.cfg.GRPCEndpoints = make(map[string]string)
	}
	p.cfg.GRPCEndpoints[network] = grpcURL
	p.verifier.grpcURLs[network] = grpcURL
	p.verifier.networks = append(p.verifier.networks, network)

	if p.cfg.RESTEndpoints == nil {
		p.cfg.RESTEndpoints = make(map[string]string)
	}
	p.cfg.RESTEndpoints[network] = restURL

	p.settler.cfg.GRPCEndpoints[network] = grpcURL
	p.settler.cfg.RESTEndpoints[network] = restURL
	p.settler.networks = append(p.settler.networks, network)

	p.log.Info("added cosmos network", "network", network)
}

func (p *Provider) restURL(network string) string {
	if u := p.cfg.RESTEndpoints[network]; u != "" {
		return strings.TrimRight(u, "/")
	}
	return strings.TrimRight(RESTFromNetwork(network), "/")
}

func (p *Provider) fetchBlock(ctx context.Context, network, url string) (x402.BlockInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return x402.BlockInfo{}, err
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return x402.BlockInfo{}, fmt.Errorf("get block: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return x402.BlockInfo{}, err
	}

	var result struct {
		Block struct {
			Header struct {
				Height string `json:"height"`
				Time   string `json:"time"`
			} `json:"header"`
			Data struct {
				Txs []json.RawMessage `json:"txs"`
			} `json:"data"`
		} `json:"block"`
		BlockID struct {
			Hash string `json:"hash"`
		} `json:"block_id"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return x402.BlockInfo{}, fmt.Errorf("parse block response: %w", err)
	}

	var height int64
	fmt.Sscanf(result.Block.Header.Height, "%d", &height)
	ts, _ := time.Parse(time.RFC3339Nano, result.Block.Header.Time)

	return x402.BlockInfo{
		Network:   network,
		Height:    height,
		Hash:      result.BlockID.Hash,
		Timestamp: ts.UTC(),
		TxCount:   len(result.Block.Data.Txs),
	}, nil
}
