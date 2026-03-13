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
	"github.com/vitwit/x402/utils"
)

// X402 is the main struct that provides all x402 functionality
type X402 struct {
	verification *verification.VerificationService
	settlement   *settlement.SettlementService

	logger  logger.Logger
	metrics metrics.Recorder
	timeout time.Duration

	config *types.X402Config

	// V2: Lifecycle Hooks
	hooks map[types.HookType][]types.HookFunc

	// V2: Plugin Registry
	networks map[string]types.ChainFamily
	plugins  map[string]types.Plugin
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

	// Wire SIWx Verification Helpers (Plugs into agnostic types package)
	types.VerifyEVMSIWx = utils.VerifyEVMSignature
	types.VerifySolanaSIWx = utils.VerifySolanaSignature
	types.VerifyCosmosSIWx = utils.VerifyCosmosSignature

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

	x.hooks = make(map[types.HookType][]types.HookFunc)
	x.networks = make(map[string]types.ChainFamily)
	x.plugins = make(map[string]types.Plugin)

	return x
}

// RegisterPlugin registers a protocol extension (V2)
func (x *X402) RegisterPlugin(p types.Plugin) {
	x.plugins[p.ID()] = p
}

// RegisterHook registers a lifecycle hook (V2)
func (x *X402) RegisterHook(hookType types.HookType, fn types.HookFunc) {
	x.hooks[hookType] = append(x.hooks[hookType], fn)
}

// runHooks executes all hooks of a given type
func (x *X402) runHooks(ctx context.Context, hookType types.HookType, hCtx *types.HookContext) error {
	for _, fn := range x.hooks[hookType] {
		if err := fn(ctx, hCtx); err != nil {
			return err
		}
	}
	return nil
}

// AddNetwork adds support for a specific network by creating the appropriate client
func (x *X402) AddNetwork(network string, networkFamily types.ChainFamily, config types.ClientConfig) error {
	normalized := types.NormalizeNetwork(network)
	switch networkFamily {
	case types.ChainEVM:
		return x.addEVMNetwork(normalized, config)
	case types.ChainSolana:
		return x.addSolanaNetwork(normalized, config)
	case types.ChainCosmos:
		return x.addCosmosNetwork(normalized, config)
	default:
		return &types.X402Error{
			Code:    types.ErrUnsupportedNetwork,
			Message: fmt.Sprintf("unsupported network family: %v", networkFamily),
		}
	}
}

// addEVMNetwork adds an EVM network client
func (x *X402) addEVMNetwork(network string, config types.ClientConfig) error {
	client, err := clients.NewEVMClient(network, config.RPCUrl, config.HexSeed)
	if err != nil {
		return fmt.Errorf("failed to create EVM client for %s: %w", network, err)
	}

	x.plugins[network] = client // V2 Plugin Registration

	// Register with internal services
	if err := x.verification.AddEVMClient(network, client, config); err != nil {
		return err
	}
	return x.settlement.AddEVMClient(network, client, config)
}

// addSolanaNetwork adds a Solana network client
func (x *X402) addSolanaNetwork(network string, config types.ClientConfig) error {
	client, err := clients.NewSolanaClientWithFeePayer(network, config.RPCUrl, config.HexSeed)
	if err != nil {
		return fmt.Errorf("failed to create Solana client for %s: %w", network, err)
	}

	x.plugins[network] = client // V2 Plugin Registration

	// Register with internal services
	if err := x.verification.AddSolanaClient(network, client, config); err != nil {
		return err
	}
	return x.settlement.AddSolanaClient(network, client, config)
}

// addCosmosNetwork adds a Cosmos network client
func (x *X402) addCosmosNetwork(network string, config types.ClientConfig) error {
	client, err := clients.NewCosmosClient(network, config.RPCUrl, config.GRPCUrl, config.AcceptedDenom)
	if err != nil {
		return fmt.Errorf("failed to create Cosmos client for %s: %w", network, err)
	}

	x.plugins[network] = client // V2 Plugin Registration

	// Register with internal services
	if err := x.verification.AddCosmosClient(network, client, config); err != nil {
		return err
	}
	return x.settlement.AddCosmosClient(network, client, config)
}

// Verify verifies a payment against requirements
func (x *X402) Verify(
	ctx context.Context,
	payload *types.VerifyRequest,
) (*types.VerificationResult, error) {
	hCtx := &types.HookContext{
		Timestamp: time.Now(),
		Request:   payload,
	}

	if err := x.runHooks(ctx, types.HookBeforeVerify, hCtx); err != nil {
		return nil, err
	}

	// V2: Use plugin registry if available, otherwise fallback to legacy verification
	var result *types.VerificationResult
	var err error

	network := types.NormalizeNetwork(payload.PaymentRequirements.Network)
	if p, ok := x.plugins[network]; ok && p.Type() == types.PluginChain {
		// If the plugin implements a "Verify" method (not in base interface but common for chains)
		if verifier, ok := p.(interface {
			VerifyPayment(context.Context, *types.VerifyRequest) (*types.VerificationResult, error)
		}); ok {
			result, err = verifier.VerifyPayment(ctx, payload)
		}
	}

	if result == nil && err == nil {
		result, err = x.verification.Verify(ctx, payload)
	}

	hCtx.Result = result
	if err := x.runHooks(ctx, types.HookAfterVerify, hCtx); err != nil {
		return result, err
	}

	return result, err
}

// Settle settles a payment transaction
func (x *X402) Settle(
	ctx context.Context,
	payload *types.VerifyRequest,
) (*types.SettlementResult, error) {
	hCtx := &types.HookContext{
		Timestamp: time.Now(),
		Request:   payload,
	}

	if err := x.runHooks(ctx, types.HookBeforeSettle, hCtx); err != nil {
		return nil, err
	}

	// V2: Use plugin registry if available
	var result *types.SettlementResult
	var err error

	network := types.NormalizeNetwork(payload.PaymentRequirements.Network)
	if p, ok := x.plugins[network]; ok && p.Type() == types.PluginChain {
		if settler, ok := p.(interface {
			SettlePayment(context.Context, *types.VerifyRequest) (*types.SettlementResult, error)
		}); ok {
			result, err = settler.SettlePayment(ctx, payload)
		}
	}

	if result == nil && err == nil {
		result, err = x.settlement.Settle(ctx, payload)
	}

	hCtx.Result = result
	if err := x.runHooks(ctx, types.HookAfterSettle, hCtx); err != nil {
		return result, err
	}

	return result, err
}

// BatchVerify verifies multiple payments concurrently
func (x *X402) BatchVerify(
	ctx context.Context,
	payload []*types.VerifyRequest,
) ([]*types.VerificationResult, error) {
	return nil, &types.X402Error{
		Code:    types.ErrNotImplemented,
		Message: "BatchVerify not implemented",
	}
}

// BatchSettle settles multiple payments concurrently
func (x *X402) BatchSettle(
	ctx context.Context,
	requests []*types.VerifyRequest,
) ([]*types.SettlementResult, error) {
	return nil, &types.X402Error{
		Code:    types.ErrNotImplemented,
		Message: "BatchSettle not implemented",
	}
}

// VerifySIWx verifies a Sign-In-With-X message and signature (V2)
func (x *X402) VerifySIWx(ctx context.Context, msg *types.SIWxMessage, signature string) (bool, error) {
	return msg.Verify(signature)
}

func (x *X402) Supported() (*types.SupportedResponse, error) {
	caps := x.verification.Capabilities()

	out := make([]types.SupportedKind, 0, len(caps))

	for _, cap := range caps {
		out = append(out, types.SupportedKind{
			X402Version: cap.X402Version,
			Scheme:      string(cap.Scheme),
			Network:     cap.Network,
		})
	}

	return &types.SupportedResponse{
		Kinds: out,
	}, nil
}

// Discovery returns V2-compliant service discovery metadata
func (x *X402) Discovery() *types.ServiceMetadata {
	caps := x.verification.Capabilities()
	endpoints := make([]types.EndpointMetadata, 0)

	// In a real implementation, this would be populated from actual protected resources.
	// For this SDK, we'll generate metadata based on supported networks for a generic endpoint.
	for _, cap := range caps {
		endpoints = append(endpoints, types.EndpointMetadata{
			Path:   "/api/protected",
			Method: "POST",
			Requirements: []types.PaymentRequired{
				{
					X402Version: 2,
					Accepts: []types.PaymentRequirements{
						{
							Scheme:            string(cap.Scheme),
							Network:           cap.Network,
							Asset:             "USDC", // Default example
							Amount:            "1.00",
							MaxTimeoutSeconds: 300,
						},
					},
				},
			},
		})
	}

	return &types.ServiceMetadata{
		X402Version: 2,
		Name:        "x402 Facilitator",
		Description: "Vitwit x402 V2 Facilitator Service",
		Endpoints:   endpoints,
	}
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
