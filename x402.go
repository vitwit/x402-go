// Package x402 provides a complete implementation of the x402 payment protocol
// for multiple blockchain networks including EVM, Solana, and Cosmos.
package x402

import (
	"context"
	"fmt"
	"time"

	"github.com/vitwit/x402/clients"
	"github.com/vitwit/x402/logger"
	"github.com/vitwit/x402/metrics"
	"github.com/vitwit/x402/settlement"
	"github.com/vitwit/x402/types"
	"github.com/vitwit/x402/verification"
)

// X402 is the main struct that provides all x402 functionality
type X402 struct {
	verification *verification.VerificationService
	settlement   *settlement.SettlementService

	logger  logger.Logger
	metrics metrics.Recorder
	timeout time.Duration

	config *types.X402Config
}

// New creates a new X402 instance with the given configuration
func New(cfg *types.X402Config, opts ...Option) *X402 {
	if cfg == nil {
		cfg = &types.X402Config{}
	}

	x := &X402{
		config:  cfg,
		timeout: 30 * time.Second,
		logger:  logger.NoopLogger{},
		metrics: metrics.NoopRecorder{},
	}
	if cfg.DefaultTimeout > 0 {
		x.timeout = cfg.DefaultTimeout
	}

	// Apply options
	for _, opt := range opts {
		opt(x)
	}

	// Wire services with injected deps
	x.verification = verification.NewVerificationService(
		x.timeout,
		x.metrics,
		x.logger,
	)

	x.settlement = settlement.NewSettlementService(
		x.timeout,
		x.metrics,
		x.logger,
	)

	return x
}

// AddNetwork adds support for a specific network by creating the appropriate client
func (x *X402) AddNetwork(network string, networkFamily types.ChainFamily, config types.ClientConfig) error {
	switch networkFamily {
	case types.ChainEVM:
		return x.addEVMNetwork(network, config)
	case types.ChainSolana:
		return x.addSolanaNetwork(network, config)
	case types.ChainCosmos:
		return x.addCosmosNetwork(network, config)
	default:
		return &types.X402Error{
			Code:    types.ErrUnsupportedNetwork,
			Message: fmt.Sprintf("unsupported network: %s", config.ChainID),
		}
	}
}

// addEVMNetwork adds an EVM network client
func (x *X402) addEVMNetwork(network string, config types.ClientConfig) error {
	client, err := clients.NewEVMClient(network, config.RPCUrl, config.HexSeed)
	if err != nil {
		return fmt.Errorf("failed to create EVM client for %s: %w", network, err)
	}

	if err := x.verification.AddEVMClient(network, client, config); err != nil {
		return err
	}

	if err := x.settlement.AddEVMClient(network, client, config); err != nil {
		return err
	}

	return nil
}

// addSolanaNetwork adds a Solana network client
func (x *X402) addSolanaNetwork(network string, config types.ClientConfig) error {
	client, err := clients.NewSolanaClientWithFeePayer(network, config.RPCUrl, config.HexSeed)
	if err != nil {
		return fmt.Errorf("failed to create Solana client for %s: %w", network, err)
	}

	if err := x.verification.AddSolanaClient(network, client, config); err != nil {
		return err
	}

	if err := x.settlement.AddSolanaClient(network, client, config); err != nil {
		return err
	}

	return nil
}

// addCosmosNetwork adds a Cosmos network client
func (x *X402) addCosmosNetwork(network string, config types.ClientConfig) error {
	client, err := clients.NewCosmosClient(network, config.RPCUrl, config.GRPCUrl, config.AcceptedDenom)
	if err != nil {
		return fmt.Errorf("failed to create Cosmos client for %s: %w", network, err)
	}

	if err := x.verification.AddCosmosClient(network, client, config); err != nil {
		return err
	}

	if err := x.settlement.AddCosmosClient(network, client, config); err != nil {
		return err
	}

	return nil
}

// Verify verifies a payment against requirements
func (x *X402) Verify(
	ctx context.Context,
	payload *types.VerifyRequest,
) (*types.VerificationResult, error) {
	return x.verification.Verify(ctx, payload)
}

// Settle settles a payment transaction
func (x *X402) Settle(
	ctx context.Context,
	payload *types.VerifyRequest,
) (*types.SettlementResult, error) {
	return x.settlement.Settle(ctx, payload)
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

	panic("not implemented")
}

// BatchSettle settles multiple payments concurrently
func (x *X402) BatchSettle(
	ctx context.Context,
	requests []*types.VerifyRequest,
) ([]*types.SettlementResult, error) {
	panic("not implemented")
}

func (x *X402) Supported() (*types.SupportedResponse, error) {
	caps := x.verification.Capabilities()

	out := make([]types.SupportedItem, 0, len(caps))

	for _, cap := range caps {
		out = append(out, types.SupportedItem{
			X402Version: cap.X402Version,
			Scheme:      string(cap.Scheme),
			Network:     cap.Network,
		})
	}

	return &types.SupportedResponse{
		Kinds: out,
	}, nil
}

// IsNetworkSupported checks if a network is supported
func (x *X402) IsNetworkSupported(network string) bool {
	return x.verification.IsNetworkSupported(network) &&
		x.settlement.IsNetworkSupported(network)
}

// EstimateSettlementGas estimates gas costs for a settlement
func (x *X402) EstimateSettlementGas(
	ctx context.Context,
	request *types.VerifyRequest,
) (uint64, error) {
	gasLimit, _, err := x.settlement.EstimateGas(ctx, request)
	return gasLimit, err
}

// Close closes all client connections
func (x *X402) Close() {
	x.verification.Close()
	x.settlement.Close()
}
