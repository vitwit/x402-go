package types

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/shopspring/decimal"
)

// X402VersionConst represents the version of the x402 protocol
type X402VersionConst int

const (
	X402Version1 X402VersionConst = 1
	X402Version2 X402VersionConst = 2
)

// x402 Header Constants (V2)
const (
	HeaderPaymentRequired  = "PAYMENT-REQUIRED"
	HeaderPaymentSignature = "PAYMENT-SIGNATURE"
	HeaderPaymentResponse  = "PAYMENT-RESPONSE"
	HeaderSignInWithX      = "SIGN-IN-WITH-X"
	HeaderSessionID        = "X-SESSION-ID"
)

// ============================================================================
// Plugin System (V2)
// ============================================================================

// Plugin defines the interface for x402 protocol extensions (chains, schemes)
type Plugin interface {
	ID() string
	Type() PluginType
	Initialize(ctx context.Context, config interface{}) error
}

type PluginType string

const (
	PluginChain  PluginType = "chain"
	PluginScheme PluginType = "scheme"
	PluginAsset  PluginType = "asset"
)

// PaymentScheme represents different payment schemes
type PaymentScheme string

const (
	SchemeExact PaymentScheme = "exact"
)

// TokenStandard represents different token standards
type TokenStandard string

const (
	TokenStandardERC20  TokenStandard = "erc20"
	TokenStandardSPL    TokenStandard = "spl"
	TokenStandardCW20   TokenStandard = "cw20"
	TokenStandardNative TokenStandard = "native"
)

// ============================================================================
// View Interfaces (matching Coinbase)
// ============================================================================

// PaymentRequirementsView is a unified interface for payment requirements.
// Both V1 and V2 types implement this to work with selectors/policies/hooks.
type PaymentRequirementsView interface {
	GetScheme() string
	GetNetwork() string // Returns network as string
	GetAsset() string
	GetAmount() string // V1: MaxAmountRequired, V2: Amount
	GetPayTo() string
	GetMaxTimeoutSeconds() int
	GetExtra() map[string]interface{}
}

// PaymentPayloadView is a unified interface for payment payloads.
// Both V1 and V2 types implement this to work with hooks.
type PaymentPayloadView interface {
	GetVersion() int
	GetScheme() string
	GetNetwork() string
	GetPayload() map[string]interface{}
}

// PaymentRequirementsSelector chooses which payment option to use.
// Works with unified view interface.
type PaymentRequirementsSelector func(requirements []PaymentRequirementsView) PaymentRequirementsView

// PaymentPolicy filters or transforms payment requirements.
// Works with unified view interface.
type PaymentPolicy func(requirements []PaymentRequirementsView) []PaymentRequirementsView

// DefaultPaymentSelector chooses the first available payment option.
func DefaultPaymentSelector(requirements []PaymentRequirementsView) PaymentRequirementsView {
	if len(requirements) == 0 {
		panic("no payment requirements available")
	}
	return requirements[0]
}

// ============================================================================
// Lifecycle Hooks (V2)
// ============================================================================

// HookType defines the type of lifecycle hook
type HookType string

const (
	HookBeforeVerify HookType = "beforeVerify"
	HookAfterVerify  HookType = "afterVerify"
	HookBeforeSettle HookType = "beforeSettle"
	HookAfterSettle  HookType = "afterSettle"
)

// HookContext provides context information to lifecycle hooks
type HookContext struct {
	Timestamp time.Time
	Request   *VerifyRequest
	Result    interface{} // VerificationResult or SettlementResult
	Headers   map[string]string
}

// HookFunc is the function signature for a lifecycle hook
type HookFunc func(ctx context.Context, hCtx *HookContext) error

// ============================================================================
// Network type (matching Coinbase)
// ============================================================================

// Network represents a blockchain network identifier in CAIP-2 format
// Format: namespace:reference (e.g., "eip155:1" for Ethereum mainnet)
type Network string

// Parse splits the network into namespace and reference components
func (n Network) Parse() (namespace, reference string, err error) {
	parts := strings.Split(string(n), ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid network format: %s", n)
	}
	return parts[0], parts[1], nil
}

// Match checks if this network matches a pattern (supports wildcards)
func (n Network) Match(pattern Network) bool {
	if n == pattern {
		return true
	}

	nStr := string(n)
	patternStr := string(pattern)

	if strings.HasSuffix(patternStr, ":*") {
		prefix := strings.TrimSuffix(patternStr, "*")
		return strings.HasPrefix(nStr, prefix)
	}

	if strings.HasSuffix(nStr, ":*") {
		prefix := strings.TrimSuffix(nStr, "*")
		return strings.HasPrefix(patternStr, prefix)
	}

	return false
}

// ============================================================================
// Verify / Settle Response types (matching Coinbase)
// ============================================================================

// VerifyResponse contains the verification result (matching Coinbase)
type VerifyResponse struct {
	IsValid        bool   `json:"isValid"`
	InvalidReason  string `json:"invalidReason,omitempty"`
	InvalidMessage string `json:"invalidMessage,omitempty"`
	Payer          string `json:"payer,omitempty"`
}

// SettleResponse contains the settlement result (matching Coinbase)
type SettleResponse struct {
	Success      bool    `json:"success"`
	ErrorReason  string  `json:"errorReason,omitempty"`
	ErrorMessage string  `json:"errorMessage,omitempty"`
	Payer        string  `json:"payer,omitempty"`
	Transaction  string  `json:"transaction"`
	Network      Network `json:"network"`
}

// ============================================================================
// ResourceConfig (matching Coinbase)
// ============================================================================

// Price represents a price that can be specified in various formats
type Price interface{}

// AssetAmount represents an amount of a specific asset
type AssetAmount struct {
	Asset  string                 `json:"asset"`
	Amount string                 `json:"amount"`
	Extra  map[string]interface{} `json:"extra,omitempty"`
}

// ResourceConfig defines payment configuration for a protected resource
type ResourceConfig struct {
	Scheme            string  `json:"scheme"`
	PayTo             string  `json:"payTo"`
	Price             Price   `json:"price"`
	Network           Network `json:"network"`
	MaxTimeoutSeconds int     `json:"maxTimeoutSeconds,omitempty"`
}

// PartialPaymentPayload contains only x402Version for version detection
type PartialPaymentPayload struct {
	X402Version int `json:"x402Version"`
}

// ============================================================================
// Internal VerifyRequest (used by vitwit's verification/settlement services)
// ============================================================================

// VerifyRequest represents the payload sent to a facilitator to verify a payment.
// This is the internal representation used by vitwit's SDK services.
type VerifyRequest struct {
	// Version of the x402 payment protocol.
	X402Version int `json:"x402Version"`

	// Payment payload (V2 format — map-based)
	PaymentPayload PaymentPayload `json:"paymentPayload"`

	// Payment requirements being verified against (V2 format)
	PaymentRequirements PaymentRequirements `json:"paymentRequirements"`

	Network string `json:"network"`
}

// Validate checks that the VerifyRequest contains all required fields.
func (v *VerifyRequest) Validate() error {
	if v.X402Version <= 0 {
		return fmt.Errorf("x402Version must be greater than 0")
	}

	if len(v.PaymentPayload.Payload) == 0 {
		return fmt.Errorf("PaymentPayload is required")
	}

	if v.PaymentRequirements.Scheme == "" {
		return fmt.Errorf("paymentRequirements.scheme is required")
	}

	if v.PaymentRequirements.Network == "" {
		return fmt.Errorf("paymentRequirements.network is required")
	}

	if v.PaymentRequirements.PayTo == "" {
		return fmt.Errorf("paymentRequirements.payTo is required")
	}

	if v.PaymentRequirements.Asset == "" {
		return fmt.Errorf("paymentRequirements.asset is required")
	}

	if v.PaymentRequirements.MaxTimeoutSeconds <= 0 {
		return fmt.Errorf("paymentRequirements.maxTimeoutSeconds must be greater than 0")
	}

	return nil
}

// ============================================================================
// Chain-specific payment payload types (vitwit extensions for Cosmos/Solana/EVM)
// ============================================================================

type CosmosPaymentPayload struct {
	Version   int               `json:"version"`
	ChainID   string            `json:"chainId"`
	Payment   CosmosPaymentData `json:"payment"`
	Signature string            `json:"signature"`
}

type CosmosPaymentData struct {
	Amount        string `json:"amount"`
	Denom         string `json:"denom"`
	Payer         string `json:"payer"`
	Recipient     string `json:"recipient"`
	TxBase64      string `json:"txBase64"`
	PublicKey     string `json:"publicKey"`
	Fee           string `json:"fee,omitempty"`
	Gas           string `json:"gas,omitempty"`
	Memo          string `json:"memo,omitempty"`
	Sequence      string `json:"sequence,omitempty"`
	AccountNumber string `json:"accountNumber,omitempty"`
}

type SolanaPaymentPayload struct {
	Transaction string `json:"transaction"`
}

type SolanaPaymentData struct {
	Amount          string `json:"amount"`
	Mint            string `json:"mint"`      // SPL token mint or "SOL" for native
	Payer           string `json:"payer"`     // Base58 public key of sender
	Recipient       string `json:"recipient"` // Base58 public key of receiver
	TxBase64        string `json:"txBase64"`  // base64-encoded transaction bytes
	RecentBlockhash string `json:"recentBlockhash,omitempty"`
	PublicKey       string `json:"publicKey"` // sender's public key (for verification)
	FeePayer        string `json:"feePayer,omitempty"`
	Memo            string `json:"memo,omitempty"`
}

// After decoding PaymentPayload.Payload (map → json)
type EvmPaymentPayload struct {
	Type string `json:"type"` // "raw_tx", "eip3009", "eip2612"

	RawTx          string                `json:"rawTx,omitempty"`
	EIP3009Payload *EIP3009Payload       `json:"eip3009,omitempty"`
	EIP2612Permit  *EIP2612PermitPayload `json:"eip2612,omitempty"`
}

type EIP3009Payload struct {
	Signature     string              `json:"signature"` // The 65-byte ECDSA signature (v,r,s)
	Authorization EIP3009Authorization `json:"authorization"`
}

type EIP3009Authorization struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`       // uint256
	ValidAfter  string `json:"validAfter"`  // uint256 timestamp
	ValidBefore string `json:"validBefore"` // uint256 timestamp
	Nonce       string `json:"nonce"`       // bytes32
}

type EIP2612PermitPayload struct {
	Owner     string `json:"owner"`
	Spender   string `json:"spender"`
	Value     string `json:"value"` // uint256 in string
	Nonce     string `json:"nonce"`
	Deadline  string `json:"deadline"`  // uint256
	Signature string `json:"signature"` // 0x + r||s||v
}

type EVMRawTxPayload struct {
	RawTx string `json:"rawTx"`
}

// EthereumPermitPayload represents an x402-compatible payload
// for Ethereum-based payments using EIP-712 + EIP-2612 / EIP-3009
type EthereumPermitPayload struct {
	Authorization EVMAuthorization  `json:"authorization"`
	Signature     string            `json:"signature"`       // Hex or base64 signature
	Extra         map[string]string `json:"extra,omitempty"` // Optional metadata
}

type EVMAuthorization struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  int    `json:"validAfter"`
	ValidBefore int    `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

// EIP712Domain defines the domain separator per EIP-712
type EIP712Domain struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	ChainId           string `json:"chainId"`
	VerifyingContract string `json:"verifyingContract"`
}

// EIP712PermitMsg covers both EIP-2612 and EIP-3009 message types
type EIP712PermitMsg struct {
	Owner       string `json:"owner,omitempty"`       // EIP-2612
	Spender     string `json:"spender,omitempty"`     // EIP-2612
	From        string `json:"from,omitempty"`        // EIP-3009
	To          string `json:"to,omitempty"`          // EIP-3009
	Value       string `json:"value"`                 // amount in wei (as string)
	ValidAfter  string `json:"validAfter,omitempty"`  // EIP-3009
	ValidBefore string `json:"validBefore,omitempty"` // EIP-3009
	Nonce       string `json:"nonce"`                 // EIP-2612 or EIP-3009
	Deadline    string `json:"deadline,omitempty"`     // EIP-2612
}

// ============================================================================
// Token & Amount types
// ============================================================================

// TokenInfo contains information about the payment token
type TokenInfo struct {
	Standard    TokenStandard `json:"standard" validate:"required"`
	Address     string        `json:"address,omitempty"` // Contract address for tokens, empty for native
	Symbol      string        `json:"symbol" validate:"required"`
	Decimals    int           `json:"decimals" validate:"required"`
	Name        string        `json:"name,omitempty"`
	ChainID     string        `json:"chainId,omitempty"`
	CoingeckoID string        `json:"coingeckoId,omitempty"`
	LogoURL     string        `json:"logoUrl,omitempty"`
	Verified    bool          `json:"verified,omitempty"`
}

// Amount represents payment amounts with support for ranges
type Amount struct {
	// For exact payments
	Value *decimal.Decimal `json:"value,omitempty"`

	// For range payments
	Min *decimal.Decimal `json:"min,omitempty"`
	Max *decimal.Decimal `json:"max,omitempty"`

	// For any amount
	Currency string `json:"currency,omitempty"`
}

// ExtraData contains additional payment-specific data
type ExtraData map[string]interface{}

// ============================================================================
// Internal SDK result types (used by verification/settlement services)
// ============================================================================

// VerificationResult contains the result of payment verification
type VerificationResult struct {
	IsValid       bool       `json:"isValid"`
	InvalidReason string     `json:"invalidReason"`
	Amount        string     `json:"amount,omitempty"`
	Token         string     `json:"token,omitempty"`
	Recipient     string     `json:"recipient,omitempty"`
	Sender        string     `json:"sender,omitempty"`
	Timestamp     *time.Time `json:"timestamp,omitempty"`
	Confirmations int        `json:"confirmations,omitempty"`
	Error         string     `json:"error,omitempty"`
	Extra         ExtraData  `json:"extra,omitempty"`
	Payer         string     `json:"payer,omitempty"`
	Fees          string     `json:"fees,omitempty"`
}

// PriorityLevel represents transaction priority
type PriorityLevel string

const (
	PriorityLow    PriorityLevel = "low"
	PriorityMedium PriorityLevel = "medium"
	PriorityHigh   PriorityLevel = "high"
	PriorityUrgent PriorityLevel = "urgent"
)

// SettlementResult contains the result of payment settlement
type SettlementResult struct {
	Success   bool      `json:"success"`
	TxHash    string    `json:"txHash,omitempty"`
	NetworkId string    `json:"networkId,omitempty"`
	Error     string    `json:"error,omitempty"`
	Extra     ExtraData `json:"extra,omitempty"`

	Amount        string     `json:"amount,omitempty"`
	Asset         string     `json:"asset,omitempty"`
	Recipient     string     `json:"recipient,omitempty"`
	Sender        string     `json:"sender,omitempty"`
	Timestamp     *time.Time `json:"timestamp,omitempty"`
	Confirmations int        `json:"confirmations,omitempty"`
	Fees          string     `json:"fees,omitempty"`
}

// ============================================================================
// Client/Config types
// ============================================================================

// ClientConfig contains configuration for blockchain clients
type ClientConfig struct {
	Network       string            `json:"network"`
	RPCUrl        string            `json:"rpcUrl"`
	GRPCUrl       string            `json:"grpcUrl,omitempty"`
	WSUrl         string            `json:"wsUrl,omitempty"`
	ChainID       string            `json:"chainId,omitempty"`
	Timeout       time.Duration     `json:"timeout,omitempty"`
	RetryCount    int               `json:"retryCount,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Extra         ExtraData         `json:"extra,omitempty"`
	AcceptedDenom string            `json:"acceptedDenom"`
	HexSeed       string            `json:"hexSeed"`
	ChainFamily   ChainFamily       `json:"chainFamily"`
	Scheme        string            `json:"scheme"`
	PayTo         string            `json:"payTo"`
	X402Version   int               `json:"x402Version"`
}

// X402Config contains global configuration for the x402 library
type X402Config struct {
	DefaultTimeout time.Duration           `json:"defaultTimeout,omitempty"`
	RetryCount     int                     `json:"retryCount,omitempty"`
	Clients        map[string]ClientConfig `json:"clients,omitempty"`
	LogLevel       string                  `json:"logLevel,omitempty"`
	EnableMetrics  bool                    `json:"enableMetrics,omitempty"`
	Extra          ExtraData               `json:"extra,omitempty"`
}

// ============================================================================
// Error types
// ============================================================================

type X402Error struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (e X402Error) Error() string {
	return e.Message
}

// Common error codes
const (
	ErrInvalidPayload      = "INVALID_PAYLOAD"
	ErrInvalidRequirements = "INVALID_REQUIREMENTS"
	ErrUnsupportedNetwork  = "UNSUPPORTED_NETWORK"
	ErrInsufficientAmount  = "INSUFFICIENT_AMOUNT"
	ErrExpiredPayment      = "EXPIRED_PAYMENT"
	ErrVerificationFailed  = "VERIFICATION_FAILED"
	ErrSettlementFailed    = "SETTLEMENT_FAILED"
	ErrNetworkError        = "NETWORK_ERROR"
	ErrConfigError         = "CONFIG_ERROR"
	ErrNotImplemented      = "NOT_IMPLEMENTED"
)

// ============================================================================
// Resource Server Extension interface (matching Coinbase)
// ============================================================================

// ResourceServerExtension interface for protocol extensions
type ResourceServerExtension interface {
	Key() string
	EnrichDeclaration(declaration interface{}, transportContext interface{}) interface{}
}

// ============================================================================
// Discovery Meta (V2)
// ============================================================================

// ServiceMetadata defines x402 service discovery metadata (V2)
type ServiceMetadata struct {
	X402Version int                    `json:"x402Version"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Icon        string                 `json:"icon,omitempty"`
	Website     string                 `json:"website,omitempty"`
	Endpoints   []EndpointMetadata     `json:"endpoints"`
	Extensions  map[string]interface{} `json:"extensions,omitempty"`
}

// EndpointMetadata defines metadata for a specific payment-protected endpoint
type EndpointMetadata struct {
	Path         string           `json:"path"`
	Method       string           `json:"method"`
	Requirements []PaymentRequired `json:"requirements"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// ============================================================================
// Wallet & Sessions (V2)
// ============================================================================

// SessionInfo defines a wallet-controlled session (V2)
type SessionInfo struct {
	ID        string    `json:"sessionId"`
	Address   string    `json:"address"`
	Network   Network   `json:"network"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Proof     string    `json:"proof,omitempty"` // SIWx proof
}

// SIWxMessage defines the structure of a Sign-In-With-X message (CAIP-122)
type SIWxMessage struct {
	Domain    string    `json:"domain"`
	Address   string    `json:"address"`
	Statement string    `json:"statement,omitempty"`
	URI       string    `json:"uri"`
	Version   string    `json:"version"`
	ChainID   string    `json:"chainId"`
	Nonce     string    `json:"nonce"`
	IssuedAt  time.Time `json:"issuedAt"`
}

// String returns the SIWx message as a standard string for signing
func (m *SIWxMessage) String() string {
	var b strings.Builder
	
	// Determine network name for the template
	networkName := "Ethereum" // Default
	if strings.HasPrefix(m.ChainID, "solana:") {
		networkName = "Solana"
	} else if strings.HasPrefix(m.ChainID, "cosmos:") {
		networkName = "Cosmos"
	}

	b.WriteString(fmt.Sprintf("%s wants you to sign in with your %s account:\n", m.Domain, networkName))
	b.WriteString(m.Address + "\n\n")

	if m.Statement != "" {
		b.WriteString(m.Statement + "\n\n")
	}

	b.WriteString(fmt.Sprintf("URI: %s\n", m.URI))
	b.WriteString(fmt.Sprintf("Version: %s\n", m.Version))
	b.WriteString(fmt.Sprintf("Chain ID: %s\n", m.ChainID))
	b.WriteString(fmt.Sprintf("Nonce: %s\n", m.Nonce))
	b.WriteString(fmt.Sprintf("Issued At: %s", m.IssuedAt.Format(time.RFC3339)))

	return b.String()
}

// Verify verifies the SIWx message against a signature (V2)
func (m *SIWxMessage) Verify(signature string) (bool, error) {
	if signature == "" || m.Address == "" || m.Nonce == "" {
		return false, nil
	}

	// Reconstruct the message string
	message := m.String()

	// Generic verification based on ChainID prefix
	if strings.HasPrefix(m.ChainID, "eip155:") {
		// EVM verification
		return VerifyEVMSIWx(message, signature, m.Address)
	} else if strings.HasPrefix(m.ChainID, "solana:") {
		// Solana verification
		return VerifySolanaSIWx(message, signature, m.Address)
	} else if strings.HasPrefix(m.ChainID, "cosmos:") {
		// Cosmos verification
		return VerifyCosmosSIWx(message, signature, m.Address)
	}

	return false, fmt.Errorf("unsupported chain for SIWx verification: %s", m.ChainID)
}

// Placeholder verification functions to be implemented in utils/crypto.go
var (
	VerifyEVMSIWx    func(message, signature, address string) (bool, error)
	VerifySolanaSIWx func(message, signature, address string) (bool, error)
	VerifyCosmosSIWx func(message, signature, address string) (bool, error)
)
