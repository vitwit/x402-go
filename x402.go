// Package x402 provides a complete implementation of the x402 payment protocol
// for multiple blockchain networks including EVM, Solana, and Cosmos.
package x402

import (
	"context"
	"fmt"
	"time"

	"github.com/shopspring/decimal"
	"github.com/vitwit/x402/clients"
	"github.com/vitwit/x402/settlement"
	"github.com/vitwit/x402/types"
	"github.com/vitwit/x402/utils"
	"github.com/vitwit/x402/verification"
)

// X402 is the main struct that provides all x402 functionality
type X402 struct {
	verificationService *verification.VerificationService
	settlementService   *settlement.SettlementService
	config             *types.X402Config
}

// New creates a new X402 instance with the given configuration
func New(config *types.X402Config) *X402 {
	timeout := 30 * time.Second
	if config != nil && config.DefaultTimeout > 0 {
		timeout = config.DefaultTimeout
	}

	return &X402{
		verificationService: verification.NewVerificationService(timeout),
		settlementService:   settlement.NewSettlementService(timeout),
		config:             config,
	}
}

// NewWithDefaults creates a new X402 instance with default configuration
func NewWithDefaults() *X402 {
	return New(&types.X402Config{
		DefaultTimeout: 30 * time.Second,
		RetryCount:     3,
		LogLevel:       "info",
		EnableMetrics:  false,
	})
}

// AddNetwork adds support for a specific network by creating the appropriate client
func (x *X402) AddNetwork(network types.Network, config types.ClientConfig) error {
	switch {
	case network.IsEVM():
		return x.addEVMNetwork(network, config)
	case network.IsSolana():
		return x.addSolanaNetwork(network, config)
	case network.IsCosmos():
		return x.addCosmosNetwork(network, config)
	default:
		return &types.X402Error{
			Code:    types.ErrUnsupportedNetwork,
			Message: fmt.Sprintf("unsupported network: %s", network),
		}
	}
}

// addEVMNetwork adds an EVM network client
func (x *X402) addEVMNetwork(network types.Network, config types.ClientConfig) error {
	client, err := clients.NewMinimalEVMClient(network, config.RPCUrl)
	if err != nil {
		return fmt.Errorf("failed to create EVM client for %s: %w", network, err)
	}

	if err := x.verificationService.AddEVMClient(network, client); err != nil {
		return err
	}

	if err := x.settlementService.AddEVMClient(network, client); err != nil {
		return err
	}

	return nil
}

// addSolanaNetwork adds a Solana network client
func (x *X402) addSolanaNetwork(network types.Network, config types.ClientConfig) error {
	client, err := clients.NewMinimalSolanaClient(network, config.RPCUrl)
	if err != nil {
		return fmt.Errorf("failed to create Solana client for %s: %w", network, err)
	}

	if err := x.verificationService.AddSolanaClient(network, client); err != nil {
		return err
	}

	if err := x.settlementService.AddSolanaClient(network, client); err != nil {
		return err
	}

	return nil
}

// addCosmosNetwork adds a Cosmos network client
func (x *X402) addCosmosNetwork(network types.Network, config types.ClientConfig) error {
	client, err := clients.NewMinimalCosmosClient(network, config.RPCUrl)
	if err != nil {
		return fmt.Errorf("failed to create Cosmos client for %s: %w", network, err)
	}

	if err := x.verificationService.AddCosmosClient(network, client); err != nil {
		return err
	}

	if err := x.settlementService.AddCosmosClient(network, client); err != nil {
		return err
	}

	return nil
}

// Verify verifies a payment against requirements
func (x *X402) Verify(
	ctx context.Context,
	payloadJSON []byte,
	requirementsJSON []byte,
) (*types.VerificationResult, error) {
	// Parse payload
	payload, err := utils.ParsePaymentPayload(payloadJSON)
	if err != nil {
		return &types.VerificationResult{
			Valid: false,
			Error: fmt.Sprintf("failed to parse payload: %v", err),
		}, nil
	}

	// Parse requirements
	requirements, err := utils.ParsePaymentRequirements(requirementsJSON)
	if err != nil {
		return &types.VerificationResult{
			Valid: false,
			Error: fmt.Sprintf("failed to parse requirements: %v", err),
		}, nil
	}

	return x.verificationService.Verify(ctx, payload, requirements)
}

// VerifyWithObjects verifies a payment using Go objects instead of JSON
func (x *X402) VerifyWithObjects(
	ctx context.Context,
	payload *types.PaymentPayload,
	requirements *types.PaymentRequirements,
) (*types.VerificationResult, error) {
	return x.verificationService.Verify(ctx, payload, requirements)
}

// Settle settles a payment transaction
func (x *X402) Settle(
	ctx context.Context,
	payloadJSON []byte,
	requirementsJSON []byte,
	privateKey string,
	options *types.SettlementOptions,
) (*types.SettlementResult, error) {
	// Parse payload
	payload, err := utils.ParsePaymentPayload(payloadJSON)
	if err != nil {
		return &types.SettlementResult{
			Success: false,
			Error:   fmt.Sprintf("failed to parse payload: %v", err),
			Timestamp: time.Now(),
		}, nil
	}

	// Parse requirements
	requirements, err := utils.ParsePaymentRequirements(requirementsJSON)
	if err != nil {
		return &types.SettlementResult{
			Success: false,
			Error:   fmt.Sprintf("failed to parse requirements: %v", err),
			Timestamp: time.Now(),
		}, nil
	}

	// Create settlement request
	request := &types.SettlementRequest{
		PaymentPayload:      *payload,
		PaymentRequirements: *requirements,
		PrivateKey:          privateKey,
		Options:             *options,
	}

	return x.settlementService.Settle(ctx, request)
}

// SettleWithObjects settles a payment using Go objects instead of JSON
func (x *X402) SettleWithObjects(
	ctx context.Context,
	request *types.SettlementRequest,
) (*types.SettlementResult, error) {
	return x.settlementService.Settle(ctx, request)
}

// BatchVerify verifies multiple payments concurrently
func (x *X402) BatchVerify(
	ctx context.Context,
	payloadsJSON [][]byte,
	requirementsJSON [][]byte,
) ([]*types.VerificationResult, error) {
	if len(payloadsJSON) != len(requirementsJSON) {
		return nil, &types.X402Error{
			Code:    types.ErrInvalidPayload,
			Message: "number of payloads must match number of requirements",
		}
	}

	// Parse all inputs
	payloads := make([]*types.PaymentPayload, len(payloadsJSON))
	requirements := make([]*types.PaymentRequirements, len(requirementsJSON))

	for i := range payloadsJSON {
		payload, err := utils.ParsePaymentPayload(payloadsJSON[i])
		if err != nil {
			return nil, fmt.Errorf("failed to parse payload %d: %w", i, err)
		}
		payloads[i] = payload

		reqs, err := utils.ParsePaymentRequirements(requirementsJSON[i])
		if err != nil {
			return nil, fmt.Errorf("failed to parse requirements %d: %w", i, err)
		}
		requirements[i] = reqs
	}

	return x.verificationService.BatchVerify(ctx, payloads, requirements)
}

// BatchSettle settles multiple payments concurrently
func (x *X402) BatchSettle(
	ctx context.Context,
	requests []*types.SettlementRequest,
) ([]*types.SettlementResult, error) {
	return x.settlementService.BatchSettle(ctx, requests)
}

// GetSupportedNetworks returns all networks that have configured clients
func (x *X402) GetSupportedNetworks() []types.Network {
	// Get unique networks from both services
	networkMap := make(map[types.Network]bool)

	for _, network := range x.verificationService.GetSupportedNetworks() {
		networkMap[network] = true
	}

	for _, network := range x.settlementService.GetSupportedNetworks() {
		networkMap[network] = true
	}

	networks := make([]types.Network, 0, len(networkMap))
	for network := range networkMap {
		networks = append(networks, network)
	}

	return networks
}

// GetSupportedPaymentKinds returns the payment kinds supported by this instance
func (x *X402) GetSupportedPaymentKinds() []types.SupportedPaymentKind {
	networks := x.GetSupportedNetworks()
	kinds := make([]types.SupportedPaymentKind, 0, len(networks))

	for _, network := range networks {
		kind := types.SupportedPaymentKind{
			X402Version: types.X402Version1,
			Scheme:      types.SchemeExact, // Default to exact, can be extended
			Network:     network,
			Extra:       make(types.ExtraData),
		}

		// Add network-specific extra data
		if network.IsSolana() {
			// For Solana, we could add fee payer information
			kind.Extra["feePayer"] = "facilitator"
		}

		kinds = append(kinds, kind)
	}

	return kinds
}

// IsNetworkSupported checks if a network is supported
func (x *X402) IsNetworkSupported(network types.Network) bool {
	return x.verificationService.IsNetworkSupported(network) &&
		x.settlementService.IsNetworkSupported(network)
}

// QuickVerify performs basic validation without blockchain queries
func (x *X402) QuickVerify(
	payload *types.PaymentPayload,
	requirements *types.PaymentRequirements,
) (*types.VerificationResult, error) {
	return x.verificationService.QuickVerify(payload, requirements)
}

// EstimateSettlementGas estimates gas costs for a settlement
func (x *X402) EstimateSettlementGas(
	ctx context.Context,
	request *types.SettlementRequest,
) (uint64, error) {
	gasLimit, _, err := x.settlementService.EstimateGas(ctx, request)
	return gasLimit, err
}

// Close closes all client connections
func (x *X402) Close() {
	x.verificationService.Close()
	x.settlementService.Close()
}

// Utility functions for common operations

// CreatePaymentPayload creates a PaymentPayload from common parameters
func CreatePaymentPayload(
	network types.Network,
	amount string,
	token string,
	recipient string,
	sender string,
	memo string,
	networkData interface{}, // EVM, Solana, or Cosmos specific data
) *types.PaymentPayload {
	payload := &types.PaymentPayload{
		Network:   network,
		Amount:    amount,
		Token:     token,
		Recipient: recipient,
		Sender:    sender,
		Timestamp: time.Now(),
		Memo:      memo,
	}

	// Set network-specific data
	switch data := networkData.(type) {
	case *types.EVMPaymentData:
		payload.EVM = data
	case *types.SolanaPaymentData:
		payload.Solana = data
	case *types.CosmosPaymentData:
		payload.Cosmos = data
	}

	return payload
}

// CreatePaymentRequirements creates PaymentRequirements from common parameters
func CreatePaymentRequirements(
	network types.Network,
	token types.TokenInfo,
	amount *types.Amount,
	recipient string,
	deadline *time.Time,
) *types.PaymentRequirements {
	return &types.PaymentRequirements{
		X402Version: types.X402Version1,
		Scheme:      types.SchemeExact,
		Network:     network,
		Token:       token,
		Amount:      amount,
		Recipient:   recipient,
		Deadline:    deadline,
	}
}

// ParseJSONPayload parses a JSON payload string into PaymentPayload
func ParseJSONPayload(jsonData string) (*types.PaymentPayload, error) {
	return utils.ParsePaymentPayload([]byte(jsonData))
}

// ParseJSONRequirements parses a JSON requirements string into PaymentRequirements
func ParseJSONRequirements(jsonData string) (*types.PaymentRequirements, error) {
	return utils.ParsePaymentRequirements([]byte(jsonData))
}

// SerializePayload converts a PaymentPayload to JSON string
func SerializePayload(payload *types.PaymentPayload) (string, error) {
	data, err := utils.SerializePaymentPayload(payload)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SerializeRequirements converts PaymentRequirements to JSON string
func SerializeRequirements(requirements *types.PaymentRequirements) (string, error) {
	data, err := utils.SerializePaymentRequirements(requirements)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SerializeResult converts VerificationResult to JSON string
func SerializeResult(result *types.VerificationResult) (string, error) {
	data, err := utils.SerializeVerificationResult(result)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SerializeSettlementResult converts SettlementResult to JSON string
func SerializeSettlementResult(result *types.SettlementResult) (string, error) {
	data, err := utils.SerializeSettlementResult(result)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Version information
const (
	Version      = "1.0.0"
	ProtocolVersion = 1
)

// GetVersion returns version information
func GetVersion() map[string]interface{} {
	return map[string]interface{}{
		"library_version":  Version,
		"protocol_version": ProtocolVersion,
		"supported_networks": []string{
			"polygon", "polygon-amoy",
			"base", "base-sepolia",
			"solana-mainnet", "solana-devnet",
			"cosmoshub-4", "theta-testnet-001",
		},
		"supported_schemes": []string{
			"exact", "range", "any",
		},
		"supported_standards": []string{
			"erc20", "spl", "cw20", "native",
		},
	}
}

// Example helper for testing
func CreateTestPayment() (*types.PaymentPayload, *types.PaymentRequirements) {
	// Create a sample EVM payment for testing
	payload := &types.PaymentPayload{
		Network:   types.NetworkPolygonAmoy,
		Amount:    "1.5",
		Token:     "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
		Recipient: "0x742d35Cc6634C0532925a3b8D098f69DB22B6b8B",
		Sender:    "0x8ba1f109551bD432803012645Hac136c22ABB6",
		Timestamp: time.Now(),
		Memo:      "Test payment",
		EVM: &types.EVMPaymentData{
			TransactionHash: "0x1234567890123456789012345678901234567890123456789012345678901234",
			BlockNumber:     12345678,
		},
	}

	requirements := &types.PaymentRequirements{
		X402Version: types.X402Version1,
		Scheme:      types.SchemeExact,
		Network:     types.NetworkPolygonAmoy,
		Token: types.TokenInfo{
			Standard: types.TokenStandardERC20,
			Address:  "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
			Symbol:   "USDC",
			Decimals: 6,
			Name:     "USD Coin",
		},
		Amount: &types.Amount{
			Value: DecimalFromString("1.5"),
		},
		Recipient: "0x742d35Cc6634C0532925a3b8D098f69DB22B6b8B",
	}

	return payload, requirements
}

// DecimalFromString helper function
func DecimalFromString(s string) *decimal.Decimal {
	d, _ := decimal.NewFromString(s)
	return &d
}