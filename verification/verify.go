package verification

import (
	"context"
	"fmt"
	"time"

	"github.com/vitwit/x402/clients"
	"github.com/vitwit/x402/types"
)

// Verifier interface defines the contract for payment verification
type Verifier interface {
	Verify(ctx context.Context, payload *types.VerifyRequest) (*types.VerifyResponse, error)
}

// VerificationService manages payment verification across multiple networks
type VerificationService struct {
	evmClients    map[types.Network]*clients.MinimalEVMClient
	solanaClients map[types.Network]*clients.MinimalSolanaClient
	cosmosClients map[types.Network]*clients.CosmosClient
	timeout       time.Duration
}

// NewVerificationService creates a new verification service
func NewVerificationService(timeout time.Duration) *VerificationService {
	return &VerificationService{
		evmClients:    make(map[types.Network]*clients.MinimalEVMClient),
		solanaClients: make(map[types.Network]*clients.MinimalSolanaClient),
		cosmosClients: make(map[types.Network]*clients.CosmosClient),
		timeout:       timeout,
	}
}

// AddEVMClient adds an EVM client for a specific network
func (s *VerificationService) AddEVMClient(network types.Network, client *clients.MinimalEVMClient) error {
	if !network.IsEVM() {
		return &types.X402Error{
			Code:    types.ErrUnsupportedNetwork,
			Message: fmt.Sprintf("network %s is not an EVM network", network),
		}
	}

	s.evmClients[network] = client
	return nil
}

// AddSolanaClient adds a Solana client for a specific network
func (s *VerificationService) AddSolanaClient(network types.Network, client *clients.MinimalSolanaClient) error {
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
func (s *VerificationService) AddCosmosClient(network types.Network, client *clients.CosmosClient) error {
	if !network.IsCosmos() {
		return &types.X402Error{
			Code:    types.ErrUnsupportedNetwork,
			Message: fmt.Sprintf("network %s is not a Cosmos network", network),
		}
	}

	s.cosmosClients[network] = client
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

	// TODO: Check network compatibility

	network := types.Network(payload.PaymentRequirements.Network)

	// Route to appropriate client based on network type
	switch {
	case network.IsEVM():
		return s.verifyEVMPayment(verifyCtx, payload)
	case network.IsSolana():
		return s.verifySolanaPayment(verifyCtx, payload)
	case network.IsCosmos():
		return s.verifyCosmosPayment(verifyCtx, payload)
	default:
		return &types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("unsupported network: %s", network),
		}, nil
	}
}

// verifyEVMPayment verifies an EVM payment
func (s *VerificationService) verifyEVMPayment(
	ctx context.Context,
	payload *types.VerifyRequest,
) (*types.VerificationResult, error) {
	network := types.Network(payload.PaymentRequirements.Network)

	client, exists := s.evmClients[network]
	if !exists {
		return &types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("no EVM client configured for network %s", network),
		}, nil
	}

	result, err := client.VerifyPayment(ctx, payload)
	if err != nil {
		return &types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("EVM verification error: %v", err),
		}, nil
	}

	return result, nil
}

// verifySolanaPayment verifies a Solana payment
func (s *VerificationService) verifySolanaPayment(
	ctx context.Context,
	payload *types.VerifyRequest,
) (*types.VerificationResult, error) {
	network := types.Network(payload.PaymentRequirements.Network)

	client, exists := s.solanaClients[network]
	if !exists {
		return &types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("no Solana client configured for network %s", network),
		}, nil
	}

	result, err := client.VerifyPayment(ctx, payload)
	if err != nil {
		return &types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("Solana verification error: %v", err),
		}, nil
	}

	return result, nil
}

// verifyCosmosPayment verifies a Cosmos payment
func (s *VerificationService) verifyCosmosPayment(
	ctx context.Context,
	payload *types.VerifyRequest,
) (*types.VerificationResult, error) {
	network := types.Network(payload.PaymentRequirements.Network)

	client, exists := s.cosmosClients[network]
	if !exists {
		return &types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("no Cosmos client configured for network %s", network),
		}, nil
	}

	result, err := client.VerifyPayment(ctx, payload)
	if err != nil {
		return &types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("Cosmos verification error: %v", err),
		}, nil
	}

	return result, nil
}

// BatchVerify verifies multiple payments concurrently
func (s *VerificationService) BatchVerify(
	ctx context.Context,
	payloads []*types.VerifyRequest,
) ([]*types.VerificationResult, error) {

	results := make([]*types.VerificationResult, len(payloads))
	errors := make([]error, len(payloads))

	// Create a channel to collect results
	type verificationResult struct {
		index  int
		result *types.VerificationResult
		err    error
	}

	resultChan := make(chan verificationResult, len(payloads))

	// Start verification goroutines
	for i, payload := range payloads {
		go func(index int, p *types.VerifyRequest) {
			result, err := s.Verify(ctx, p)
			resultChan <- verificationResult{
				index:  index,
				result: result,
				err:    err,
			}
		}(i, payload)
	}

	// Collect results
	for i := 0; i < len(payloads); i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-resultChan:
			results[res.index] = res.result
			errors[res.index] = res.err
		}
	}

	// Check for any critical errors
	for _, err := range errors {
		if err != nil {
			return results, err
		}
	}

	return results, nil
}

// GetSupportedNetworks returns all networks that have configured clients
func (s *VerificationService) GetSupportedNetworks() []types.Network {
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

// IsNetworkSupported checks if a network is supported
func (s *VerificationService) IsNetworkSupported(network types.Network) bool {
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

// VerifyWithRetry verifies a payment with retry logic
func (s *VerificationService) VerifyWithRetry(
	ctx context.Context,
	payload *types.VerifyRequest,
	maxRetries int,
	retryDelay time.Duration,
) (*types.VerificationResult, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retrying
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryDelay):
			}
		}

		result, err := s.Verify(ctx, payload)
		if err == nil {
			return result, nil
		}

		lastErr = err

		// Don't retry for certain types of errors
		if x402Err, ok := err.(*types.X402Error); ok {
			switch x402Err.Code {
			case types.ErrInvalidPayload, types.ErrInvalidRequirements:
				// These errors won't be fixed by retrying
				return nil, err
			}
		}
	}

	return nil, fmt.Errorf("verification failed after %d attempts: %v", maxRetries+1, lastErr)
}

// QuickVerify performs a basic verification without deep blockchain queries
// Useful for preliminary checks before expensive operations
func (s *VerificationService) QuickVerify(
	payload *types.VerifyRequest,
) (*types.VerificationResult, error) {
	// Validate basic structure
	if err := payload.Validate(); err != nil {
		return &types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("invalid payload: %v", err),
		}, nil
	}

	if err := payload.Validate(); err != nil {
		return &types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("invalid requirements: %v", err),
		}, nil
	}

	// TODO: Check network compatibility

	// Check if network is supported
	network := types.Network(payload.PaymentRequirements.Network)
	if !s.IsNetworkSupported(network) {
		return &types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("network %s is not supported", network),
		}, nil
	}

	// Check basic address formats
	if err := validateAddresses(payload, network); err != nil {
		return &types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("address validation failed: %v", err),
		}, nil
	}

	// All basic checks passed
	return &types.VerificationResult{
		IsValid: true,
		// Recipient: payload.Recipient,
		// Sender:    payload.Sender,
		// Timestamp: &payload.Timestamp,
	}, nil
}

// Helper function to validate address formats
func validateAddresses(payload *types.VerifyRequest, network types.Network) error {
	// This would use the validation functions from utils package
	// For now, just basic checks
	if payload.PaymentRequirements.PayTo == "" {
		return fmt.Errorf("recipient address is empty")
	}

	// if payload.Sender == "" {
	// 	return fmt.Errorf("sender address is empty")
	// }

	// Network-specific validations would go here
	// Using utils.ValidateAddressForNetwork(address, string(network))

	return nil
}
