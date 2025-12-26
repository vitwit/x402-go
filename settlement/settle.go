package settlement

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/vitwit/x402/clients"
	"github.com/vitwit/x402/logger"
	"github.com/vitwit/x402/metrics"
	"github.com/vitwit/x402/types"
)

// Settler interface defines the contract for payment settlement
type Settler interface {
	Settle(ctx context.Context, request *types.VerifyRequest) (*types.SettlementResult, error)
}

// SettlementService manages payment settlement across multiple networks
type SettlementService struct {
	evmClients    map[string]*clients.EVMClient
	solanaClients map[string]*clients.SolanaClient
	cosmosClients map[string]*clients.CosmosClient
	timeout       time.Duration

	metrics      metrics.Recorder
	logger       logger.Logger
	capabilities map[string]types.NetworkCapability
}

// NewSettlementService creates a new settlement service
func NewSettlementService(
	timeout time.Duration,
	recorder metrics.Recorder,
	logger logger.Logger,
) *SettlementService {
	return &SettlementService{
		evmClients:    make(map[string]*clients.EVMClient),
		solanaClients: make(map[string]*clients.SolanaClient),
		cosmosClients: make(map[string]*clients.CosmosClient),
		capabilities:  make(map[string]types.NetworkCapability),
		timeout:       timeout,
		metrics:       recorder,
		logger:        logger,
	}
}

// AddEVMClient adds an EVM client for a specific network
func (s *SettlementService) AddEVMClient(network string, client *clients.EVMClient, cfg types.ClientConfig) error {
	s.evmClients[network] = client
	s.capabilities[network] = types.NetworkCapability{
		Network:     network,
		X402Version: cfg.X402Version,
		Scheme:      cfg.Scheme,
		ChainFamily: types.ChainEVM,
	}
	return nil
}

// AddSolanaClient adds a Solana client for a specific network
func (s *SettlementService) AddSolanaClient(network string, client *clients.SolanaClient, cfg types.ClientConfig) error {
	s.solanaClients[network] = client
	s.capabilities[network] = types.NetworkCapability{
		Network:     network,
		X402Version: cfg.X402Version,
		Scheme:      cfg.Scheme,
		ChainFamily: types.ChainSolana,
	}
	return nil
}

// AddCosmosClient adds a Cosmos client for a specific network
func (s *SettlementService) AddCosmosClient(network string, client *clients.CosmosClient, cfg types.ClientConfig) error {
	s.cosmosClients[network] = client
	s.capabilities[network] = types.NetworkCapability{
		Network:     network,
		X402Version: cfg.X402Version,
		Scheme:      cfg.Scheme,
		ChainFamily: types.ChainCosmos,
	}
	return nil
}

// Settle settles a payment transaction
func (s *SettlementService) Settle(
	ctx context.Context,
	payload *types.VerifyRequest,
) (*types.SettlementResult, error) {
	// Create timeout context
	settleCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	network := payload.PaymentRequirements.Network

	// Try Cosmos first
	if client, ok := s.cosmosClients[network]; ok {
		return client.SettlePayment(settleCtx, payload)
	}

	// Try EVM
	if client, ok := s.evmClients[network]; ok {
		return client.SettlePayment(settleCtx, payload)
	}

	// Try Solana
	if client, ok := s.solanaClients[network]; ok {
		return client.SettlePayment(settleCtx, payload)
	}

	return &types.SettlementResult{
		Success:   false,
		Error:     fmt.Sprintf("no settlement client configured for network %s", network),
		NetworkId: network,
	}, nil
}

// EstimateGas estimates gas costs for a settlement
func (s *SettlementService) EstimateGas(
	ctx context.Context,
	request *types.VerifyRequest,
) (uint64, *big.Int, error) {
	return 0, nil, nil
}

// Close closes all client connections
func (s *SettlementService) Close() {
	for _, client := range s.evmClients {
		client.Close()
	}

	for _, client := range s.solanaClients {
		client.Close()
	}

	for _, client := range s.cosmosClients {
		client.Close()
	}
}

// GetSupportedNetworks returns all networks that have configured clients
func (s *SettlementService) GetSupportedNetworks() []string {
	var networks []string

	for network := range s.evmClients {
		networks = append(networks, network)
	}

	for network := range s.solanaClients {
		networks = append(networks, network)
	}

	for network := range s.cosmosClients {
		networks = append(networks, network)
	}

	return networks
}

// IsNetworkSupported checks if a network is supported for settlement
func (s *SettlementService) IsNetworkSupported(network string) bool {
	if _, ok := s.evmClients[network]; ok {
		return true
	}

	if _, ok := s.solanaClients[network]; ok {
		return true
	}

	if _, ok := s.cosmosClients[network]; ok {
		return true
	}

	return false
}
