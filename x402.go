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
	"github.com/vitwit/x402/verification"
)

var supportedNetworks []types.SupportedItem

// X402 is the main struct that provides all x402 functionality
type X402 struct {
	verificationService *verification.VerificationService
	settlementService   *settlement.SettlementService
	config              *types.X402Config
}

// New creates a new X402 instance with the given configuration
func New(config *types.X402Config) *X402 {
	timeout := 30 * time.Second
	if config != nil && config.DefaultTimeout > 0 {
		timeout = config.DefaultTimeout
	}
	supportedNetworks = make([]types.SupportedItem, 0, 10)

	return &X402{
		verificationService: verification.NewVerificationService(timeout),
		settlementService:   settlement.NewSettlementService(timeout),
		config:              config,
	}
}

// NewWithDefaults creates a new X402 instance with default configuration
func NewWithDefaults() *X402 {
	supportedNetworks = make([]types.SupportedItem, 0, 10)
	return New(&types.X402Config{
		DefaultTimeout: 30 * time.Second,
		RetryCount:     3,
		LogLevel:       "info",
		EnableMetrics:  false,
	})
}

// AddNetwork adds support for a specific network by creating the appropriate client
func (x *X402) AddNetwork(network types.Network, config types.ClientConfig) error {
	supportedNetworks = append(supportedNetworks, types.SupportedItem{
		X402Version: 1,
		Scheme:      "exact",
		Network:     network.String(),
	})

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
	client, err := clients.NewEVMClient(network, config.RPCUrl)
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
	client, err := clients.NewSolanaClient(network, config.RPCUrl)
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
	client, err := clients.NewCosmosClient(network, config.RPCUrl, config.GRPCUrl, config.AcceptedDenom)
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
	payload *types.VerifyRequest,
) (*types.VerificationResult, error) {
	return x.verificationService.Verify(ctx, payload)
}

// Settle settles a payment transaction
func (x *X402) Settle(
	ctx context.Context,
	payload *types.VerifyRequest,
) (*types.SettlementResult, error) {

	return x.settlementService.Settle(ctx, payload)
}

// BatchVerify verifies multiple payments concurrently
func (x *X402) BatchVerify(
	ctx context.Context,
	payload []*types.VerifyRequest,
) ([]*types.VerificationResult, error) {
	if len(payload) == 0 {
		return nil, &types.X402Error{
			Code:    types.ErrInvalidPayload,
			Message: "number of payloads must match number of requirements",
		}
	}

	return x.verificationService.BatchVerify(ctx, payload)
}

// BatchSettle settles multiple payments concurrently
func (x *X402) BatchSettle(
	ctx context.Context,
	requests []*types.VerifyRequest,
) ([]*types.SettlementResult, error) {
	return x.settlementService.BatchSettle(ctx, requests)
}

func (x *X402) Supported() (*types.SupportedResponse, error) {
	return &types.SupportedResponse{
		Kinds: supportedNetworks,
	}, nil
}

// IsNetworkSupported checks if a network is supported
func (x *X402) IsNetworkSupported(network types.Network) bool {
	return x.verificationService.IsNetworkSupported(network) &&
		x.settlementService.IsNetworkSupported(network)
}

// QuickVerify performs basic validation without blockchain queries
func (x *X402) QuickVerify(
	payload *types.VerifyRequest,
) (*types.VerificationResult, error) {
	return x.verificationService.QuickVerify(payload)
}

// EstimateSettlementGas estimates gas costs for a settlement
func (x *X402) EstimateSettlementGas(
	ctx context.Context,
	request *types.VerifyRequest,
) (uint64, error) {
	gasLimit, _, err := x.settlementService.EstimateGas(ctx, request)
	return gasLimit, err
}

// Close closes all client connections
func (x *X402) Close() {
	x.verificationService.Close()
	x.settlementService.Close()
}

// Version information
const (
	Version         = "1.0.0"
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

// DecimalFromString helper function
func DecimalFromString(s string) *decimal.Decimal {
	d, _ := decimal.NewFromString(s)
	return &d
}
