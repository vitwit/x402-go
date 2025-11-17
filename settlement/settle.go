package settlement

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/vitwit/x402/clients"
	"github.com/vitwit/x402/types"
)

// Settler interface defines the contract for payment settlement
type Settler interface {
	Settle(ctx context.Context, request *types.VerifyRequest) (*types.SettlementResult, error)
}

// SettlementService manages payment settlement across multiple networks
type SettlementService struct {
	evmClients map[types.Network]*clients.EVMClient
	// eth           map[types.Network]*clients.EthereumClient
	solanaClients map[types.Network]*clients.SolanaClient
	cosmosClients map[types.Network]*clients.CosmosClient
	timeout       time.Duration
	defaultGas    map[types.Network]uint64
}

// NewSettlementService creates a new settlement service
func NewSettlementService(timeout time.Duration) *SettlementService {
	return &SettlementService{
		evmClients: make(map[types.Network]*clients.EVMClient),
		// eth:           make(map[types.Network]*clients.EthereumClient),
		solanaClients: make(map[types.Network]*clients.SolanaClient),
		cosmosClients: make(map[types.Network]*clients.CosmosClient),
		timeout:       timeout,
		defaultGas:    getDefaultGasLimits(),
	}
}

// AddEVMClient adds an EVM client for a specific network
func (s *SettlementService) AddEVMClient(network types.Network, client *clients.EVMClient) error {
	if !network.IsEVM() {
		return &types.X402Error{
			Code:    types.ErrUnsupportedNetwork,
			Message: fmt.Sprintf("network %s is not an EVM network", network),
		}
	}

	s.evmClients[network] = client
	return nil
}

// func (s *SettlementService) AddETHClient(network types.Network, client *clients.EthereumClient) error {
// 	if !network.IsEVM() {
// 		return &types.X402Error{
// 			Code:    types.ErrUnsupportedNetwork,
// 			Message: fmt.Sprintf("network %s is not an EVM network", network),
// 		}
// 	}

// 	s.eth[network] = client
// 	return nil
// }

// AddSolanaClient adds a Solana client for a specific network
func (s *SettlementService) AddSolanaClient(network types.Network, client *clients.SolanaClient) error {
	if !network.IsSolana() {
		return &types.X402Error{
			Code:    types.ErrUnsupportedNetwork,
			Message: fmt.Sprintf("network %s is not a Solana network", network),
		}
	}

	s.solanaClients[network] = client
	return nil
}

// AddCosmosClient adds a Cosmos client for a specific network
func (s *SettlementService) AddCosmosClient(network types.Network, client *clients.CosmosClient) error {
	if !network.IsCosmos() {
		return &types.X402Error{
			Code:    types.ErrUnsupportedNetwork,
			Message: fmt.Sprintf("network %s is not a Cosmos network", network),
		}
	}

	s.cosmosClients[network] = client
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

	// Validate request
	// if err := s.validateSettlementRequest(request); err != nil {
	// 	return &types.SettlementResult{
	// 		Success:   false,
	// 		Error:     fmt.Sprintf("invalid settlement request: %v", err),
	// 		Timestamp: time.Now(),
	// 	}, nil
	// }

	network := types.Network(payload.PaymentRequirements.Network)

	// Route to appropriate settlement method based on network type
	switch {
	case network.IsEVM():
		return s.settleEVMPayment(settleCtx, payload)
	case network.IsSolana():
		return s.settleSolanaPayment(settleCtx, payload)
	case network.IsCosmos():
		return s.settleCosmosPayment(settleCtx, payload)

	default:
		return &types.SettlementResult{
			Success:   false,
			Error:     fmt.Sprintf("unsupported network: %s", network),
			NetworkId: payload.PaymentRequirements.Network,
		}, nil
	}
}

// settleEVMPayment settles an EVM payment
func (s *SettlementService) settleEVMPayment(
	ctx context.Context,
	request *types.VerifyRequest,
) (*types.SettlementResult, error) {

	network := types.Network(request.PaymentRequirements.Network)

	//
	// 1. Priority: EthereumClient (EIP-3009)
	//
	// if ethClient, ok := s.eth[network]; ok {
	// 	result, err := ethClient.SettlePayment(ctx, request)
	// 	if err != nil {
	// 		return &types.SettlementResult{
	// 			Success:   false,
	// 			Error:     err.Error(),
	// 			NetworkId: request.PaymentRequirements.Network,
	// 		}, nil
	// 	}
	// 	return result, nil
	// }

	//
	// 2. Fallback: Generic EVM client
	//
	if evmClient, ok := s.evmClients[network]; ok {
		result, err := evmClient.SettlePayment(ctx, request)
		if err != nil {
			return &types.SettlementResult{
				Success:   false,
				Error:     err.Error(),
				NetworkId: request.PaymentRequirements.Network,
			}, nil
		}
		return result, nil
	}

	//
	// 3. No EVM client found
	//
	return &types.SettlementResult{
		Success:   false,
		Error:     fmt.Sprintf("no settlement client found for network %s", network),
		NetworkId: request.PaymentRequirements.Network,
	}, nil
}

// settleSolanaPayment settles a Solana payment
func (s *SettlementService) settleSolanaPayment(
	ctx context.Context,
	request *types.VerifyRequest,
) (*types.SettlementResult, error) {
	network := types.Network(request.PaymentRequirements.Network)

	client, exists := s.solanaClients[network]
	if !exists {
		return &types.SettlementResult{
			Success: false,
			Error:   fmt.Sprintf("no solana client configured for network %s", network),
		}, nil
	}

	result, err := client.SettlePayment(ctx, request)
	if err != nil {
		return &types.SettlementResult{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return result, nil
}

// settleCosmosPayment settles a Cosmos payment
func (s *SettlementService) settleCosmosPayment(
	ctx context.Context,
	request *types.VerifyRequest,
) (*types.SettlementResult, error) {
	network := types.Network(request.PaymentRequirements.Network)

	client, exists := s.cosmosClients[network]
	if !exists {
		return &types.SettlementResult{
			Success: false,
			Error:   fmt.Sprintf("no Cosmos client configured for network %s", network),
		}, nil
	}

	result, err := client.SettlePayment(ctx, request)
	if err != nil {
		return &types.SettlementResult{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return result, nil
}

// BatchSettle settles multiple payments concurrently
func (s *SettlementService) BatchSettle(
	ctx context.Context,
	requests []*types.VerifyRequest,
) ([]*types.SettlementResult, error) {
	results := make([]*types.SettlementResult, len(requests))

	// Create a channel to collect results
	type settlementResult struct {
		index  int
		result *types.SettlementResult
		err    error
	}

	resultChan := make(chan settlementResult, len(requests))

	// Start settlement goroutines
	for i, request := range requests {
		go func(index int, req *types.VerifyRequest) {
			result, err := s.Settle(ctx, req)
			resultChan <- settlementResult{
				index:  index,
				result: result,
				err:    err,
			}
		}(i, request)
	}

	// Collect results
	for i := 0; i < len(requests); i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-resultChan:
			results[res.index] = res.result
			// For batch operations, we collect all results even if some fail
			// Individual failures are recorded in the result objects
		}
	}

	return results, nil
}

// EstimateGas estimates gas costs for a settlement
func (s *SettlementService) EstimateGas(
	ctx context.Context,
	request *types.VerifyRequest,
) (uint64, *big.Int, error) {
	// network := types.Network(request.PaymentRequirements.Network)

	// // Get default gas estimates based on network and operation type
	// gasLimit := s.defaultGas[network]
	// if gasLimit == 0 {
	// 	gasLimit = getDefaultGasLimits()[network]
	// }

	// // Adjust for token type
	// if request.PaymentRequirements.Token.Standard != types.TokenStandardNative {
	// 	gasLimit = gasLimit * 3 // Token transfers typically use more gas
	// }

	// // For EVM networks, we can get more accurate estimates
	// if network.IsEVM() {
	// 	if client, exists := s.evmClients[network]; exists {
	// 		// This would require implementing gas estimation in the EVM client
	// 		_ = client // Use client to estimate actual gas
	// 	}
	// }

	// // Return estimated gas and gas price
	// gasPrice := getDefaultGasPrice(network)

	// return gasLimit, gasPrice, nil

	return 0, nil, nil
}

// Helper functions

func (s *SettlementService) validateSettlementRequest(request *types.VerifyRequest) error {
	// if request == nil {
	// 	return fmt.Errorf("settlement request is nil")
	// }

	// if err := request.PaymentPayload.Validate(); err != nil {
	// 	return fmt.Errorf("invalid payment payload: %w", err)
	// }

	// if err := request.PaymentRequirements.Validate(); err != nil {
	// 	return fmt.Errorf("invalid payment requirements: %w", err)
	// }

	// if request.PrivateKey == "" {
	// 	return fmt.Errorf("private key is required")
	// }

	// // Check network compatibility
	// if request.PaymentPayload.Network != request.PaymentRequirements.Network {
	// 	return fmt.Errorf("payload network does not match requirements network")
	// }

	return nil
}

func getDefaultGasLimits() map[types.Network]uint64 {
	return map[types.Network]uint64{
		types.NetworkPolygon:       21000,
		types.NetworkPolygonAmoy:   21000,
		types.NetworkBase:          21000,
		types.NetworkBaseSepolia:   21000,
		types.NetworkSolanaMainnet: 5000,
		types.NetworkSolanaDevnet:  5000,
		types.NetworkCosmosHub:     200000,
		types.NetworkCosmosTestnet: 200000,
	}
}

func getDefaultGasPrice(network types.Network) *big.Int {
	switch network {
	case types.NetworkPolygon, types.NetworkPolygonAmoy:
		return big.NewInt(30_000_000_000) // 30 gwei
	case types.NetworkBase, types.NetworkBaseSepolia:
		return big.NewInt(1_000_000_000) // 1 gwei
	default:
		return big.NewInt(20_000_000_000) // 20 gwei
	}
}

func getRequiredConfirmations(network types.Network, requested int) int {
	if requested > 0 {
		return requested
	}

	// Default confirmations based on network
	switch network {
	case types.NetworkPolygon, types.NetworkPolygonAmoy:
		return 3
	case types.NetworkBase, types.NetworkBaseSepolia:
		return 1
	case types.NetworkSolanaMainnet, types.NetworkSolanaDevnet:
		return 1
	case types.NetworkCosmosHub, types.NetworkCosmosTestnet:
		return 1
	default:
		return 1
	}
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
func (s *SettlementService) GetSupportedNetworks() []types.Network {
	var networks []types.Network

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
func (s *SettlementService) IsNetworkSupported(network types.Network) bool {
	if network.IsEVM() {
		_, exists := s.evmClients[network]
		return exists
	}

	if network.IsSolana() {
		_, exists := s.solanaClients[network]
		return exists
	}

	if network.IsCosmos() {
		_, exists := s.cosmosClients[network]
		return exists
	}

	return false
}
