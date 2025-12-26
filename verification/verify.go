package verification

import (
	"context"
	"fmt"
	"time"

	"github.com/vitwit/x402/clients"
	"github.com/vitwit/x402/logger"
	"github.com/vitwit/x402/metrics"
	"github.com/vitwit/x402/types"
)

// Verifier interface defines the contract for payment verification
type Verifier interface {
	Verify(ctx context.Context, payload *types.VerifyRequest) (*types.VerifyResponse, error)
}

// VerificationService manages payment verification across multiple networks
type VerificationService struct {
	evmClients    map[string]*clients.EVMClient
	solanaClients map[string]*clients.SolanaClient
	cosmosClients map[string]*clients.CosmosClient
	timeout       time.Duration

	metrics metrics.Recorder
	logger  logger.Logger

	capabilities map[string]types.NetworkCapability
}

// NewVerificationService creates a new verification service
func NewVerificationService(timeout time.Duration,
	recorder metrics.Recorder,
	logger logger.Logger,
) *VerificationService {
	return &VerificationService{
		evmClients:    make(map[string]*clients.EVMClient),
		solanaClients: make(map[string]*clients.SolanaClient),
		cosmosClients: make(map[string]*clients.CosmosClient),
		timeout:       timeout,
		metrics:       recorder,
		logger:        logger,
		capabilities:  make(map[string]types.NetworkCapability),
	}
}

func (s *VerificationService) Capabilities() []types.NetworkCapability {
	var result []types.NetworkCapability = make([]types.NetworkCapability, 0, 10)
	for _, v := range s.capabilities {
		result = append(result, types.NetworkCapability{
			Network:     v.Network,
			X402Version: v.X402Version,
			Scheme:      v.Scheme,
			ChainFamily: v.ChainFamily,
		})
	}
	return result
}

// AddEVMClient adds an EVM client for a specific network
func (s *VerificationService) AddEVMClient(network string, client *clients.EVMClient, cfg types.ClientConfig) error {
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
func (s *VerificationService) AddSolanaClient(network string, client *clients.SolanaClient, cfg types.ClientConfig) error {
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
func (s *VerificationService) AddCosmosClient(network string, client *clients.CosmosClient, cfg types.ClientConfig) error {
	s.cosmosClients[network] = client
	s.capabilities[network] = types.NetworkCapability{
		Network:     network,
		X402Version: cfg.X402Version,
		Scheme:      cfg.Scheme,
		ChainFamily: types.ChainCosmos,
	}
	return nil
}

// Verify verifies a payment against requirements
func (s *VerificationService) Verify(
	ctx context.Context,
	payload *types.VerifyRequest,
) (*types.VerificationResult, error) {
	// Create timeout context
	verifyCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Validate inputs
	if err := payload.Validate(); err != nil {
		return &types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("invalid payload: %v", err),
		}, nil
	}

	network := payload.PaymentRequirements.Network

	// Try Cosmos verifier
	if client, ok := s.cosmosClients[network]; ok {
		return client.VerifyPayment(verifyCtx, payload)
	}

	// Try EVM verifier
	if client, ok := s.evmClients[network]; ok {
		return client.VerifyPayment(verifyCtx, payload)
	}

	// Try Solana verifier
	if client, ok := s.solanaClients[network]; ok {
		return client.VerifyPayment(verifyCtx, payload)
	}

	return &types.VerificationResult{
		IsValid:       false,
		InvalidReason: fmt.Sprintf("no verification client configured for network %s", network),
	}, nil
}

// IsNetworkSupported checks if a network is supported
func (s *VerificationService) IsNetworkSupported(network string) bool {
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

// Close closes all client connections
func (s *VerificationService) Close() {
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
