package types

import (
	"fmt"
	"time"

	"github.com/shopspring/decimal"
)

// X402Version represents the version of the x402 protocol
type X402Version int

const (
	X402Version1 X402Version = 1
)

// Network represents supported blockchain networks
type Network string

const (
	// EVM Networks
	NetworkPolygon     Network = "polygon"
	NetworkPolygonAmoy Network = "polygon-amoy" // testnet
	NetworkBaseSepolia Network = "base-sepolia" // testnet
	NetworkBase        Network = "base"

	// Solana Networks
	NetworkSolanaMainnet Network = "solana-mainnet"
	NetworkSolanaDevnet  Network = "solana-devnet" // testnet

	// Cosmos Networks
	NetworkCosmosHub     Network = "cosmoshub-4"
	NetworkCosmosTestnet Network = "theta-testnet-001"
	NetworkCosmosLocal   Network = "testnet"
)

// PaymentScheme represents different payment schemes
type PaymentScheme string

const (
	SchemeExact PaymentScheme = "exact"
	SchemeRange PaymentScheme = "range"
	SchemeAny   PaymentScheme = "any"
)

// TokenStandard represents different token standards
type TokenStandard string

const (
	TokenStandardERC20  TokenStandard = "erc20"
	TokenStandardSPL    TokenStandard = "spl"
	TokenStandardCW20   TokenStandard = "cw20"
	TokenStandardNative TokenStandard = "native"
)

type SupportedItem struct {
	X402Version int    `json:"x402Version"`
	Scheme      string `json:"scheme"`
	Network     string `json:"network"`
}

type SupportedResponse struct {
	Kinds []SupportedItem `json:"kinds"`
}

// PaymentRequirements defines the requirements a resource server accepts for payment.
type PaymentRequirements struct {
	// Scheme of the payment protocol to use (e.g., "exact", "stream").
	Scheme string `json:"scheme"`

	// Network of the blockchain to send payment on (e.g., "ethereum-mainnet").
	Network string `json:"network"`

	// Maximum amount required to pay for the resource in atomic units of the asset.
	// Represented as a string because Go does not support uint256.
	MaxAmountRequired string `json:"maxAmountRequired"`

	// URL of the resource to pay for.
	Resource string `json:"resource"`

	// Description of the resource being purchased.
	Description string `json:"description"`

	// MIME type of the resource response (e.g., "application/json").
	MimeType string `json:"mimeType"`

	// Output schema of the resource response, if applicable.
	OutputSchema map[string]interface{} `json:"outputSchema,omitempty"`

	// Address to which the payment must be sent.
	PayTo string `json:"payTo"`

	// Maximum time in seconds for the resource server to respond.
	MaxTimeoutSeconds int `json:"maxTimeoutSeconds"`

	// Address of the EIP-3009 compliant ERC20 contract.
	Asset string `json:"asset"`

	// Extra information about payment details specific to the scheme.
	// For the `exact` scheme on EVM, this may include fields like `name` and `version`.
	Extra map[string]interface{} `json:"extra,omitempty"`
}

// X402Response represents a server response that includes supported payment options.
type X402Response struct {
	// Version of the x402 payment protocol.
	X402Version int `json:"x402Version"`

	// List of payment requirements that the resource server accepts.
	Accepts []PaymentRequirements `json:"accepts"`

	// Message from the resource server indicating any processing error.
	Error string `json:"error"`
}

// VerifyRequest represents the payload sent to a facilitator to verify a payment.
type VerifyRequest struct {
	// Version of the x402 payment protocol.
	X402Version int `json:"x402Version"`

	// Encoded payment header from the client.
	PaymentHeader string `json:"paymentHeader"`

	// Payment requirements being verified against.
	PaymentRequirements PaymentRequirements `json:"paymentRequirements"`
}

// VerifyResponse represents the facilitator's verification result.
type VerifyResponse struct {
	// Indicates whether the payment is valid.
	IsValid bool `json:"isValid"`

	// Provides a reason if the payment is invalid, otherwise null.
	InvalidReason string `json:"invalidReason"`
}

// Validate checks that the VerifyRequest contains all required fields.
func (v *VerifyRequest) Validate() error {
	if v.X402Version <= 0 {
		return fmt.Errorf("x402Version must be greater than 0")
	}

	if v.PaymentHeader == "" {
		return fmt.Errorf("paymentHeader is required")
	}

	return v.PaymentRequirements.Validate()
}

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

// SupportedPaymentKind describes what payment types a facilitator supports
type SupportedPaymentKind struct {
	X402Version X402Version   `json:"x402Version"`
	Scheme      PaymentScheme `json:"scheme"`
	Network     Network       `json:"network"`
	Extra       ExtraData     `json:"extra,omitempty"`
}

// VerificationResult contains the result of payment verification
type VerificationResult struct {
	IsValid       bool             `json:"isValid"`
	InvalidReason string           `josn:"invalidReason"`
	Amount        *decimal.Decimal `json:"amount,omitempty"`
	Token         string           `json:"token,omitempty"`
	Recipient     string           `json:"recipient,omitempty"`
	Sender        string           `json:"sender,omitempty"`
	Timestamp     *time.Time       `json:"timestamp,omitempty"`
	Confirmations int              `json:"confirmations,omitempty"`
	Error         string           `json:"error,omitempty"`
	Extra         ExtraData        `json:"extra,omitempty"`
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
}

// ClientConfig contains configuration for blockchain clients
type ClientConfig struct {
	Network       Network           `json:"network"`
	RPCUrl        string            `json:"rpcUrl"`
	GRPCUrl       string            `json:"grpcUrl,omitempty"`
	WSUrl         string            `json:"wsUrl,omitempty"`
	ChainID       string            `json:"chainId,omitempty"`
	Timeout       time.Duration     `json:"timeout,omitempty"`
	RetryCount    int               `json:"retryCount,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Extra         ExtraData         `json:"extra,omitempty"`
	AcceptedDenom string            `json:"acceptedDenom"`
}

// X402Config contains global configuration for the x402 library
type X402Config struct {
	DefaultTimeout time.Duration            `json:"defaultTimeout,omitempty"`
	RetryCount     int                      `json:"retryCount,omitempty"`
	Clients        map[Network]ClientConfig `json:"clients,omitempty"`
	LogLevel       string                   `json:"logLevel,omitempty"`
	EnableMetrics  bool                     `json:"enableMetrics,omitempty"`
	Extra          ExtraData                `json:"extra,omitempty"`
}

// Error types
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
)

func (pr *PaymentRequirements) Validate() error {
	if pr.Scheme == "" {
		return fmt.Errorf("paymentRequirements.scheme is required")
	}

	if pr.Network == "" {
		return fmt.Errorf("paymentRequirements.network is required")
	}

	if pr.MaxAmountRequired == "" {
		return fmt.Errorf("paymentRequirements.maxAmountRequired is required")
	}

	if pr.PayTo == "" {
		return fmt.Errorf("paymentRequirements.payTo is required")
	}

	if pr.Asset == "" {
		return fmt.Errorf("paymentRequirements.asset is required")
	}

	if pr.MaxTimeoutSeconds <= 0 {
		return fmt.Errorf("paymentRequirements.maxTimeoutSeconds must be greater than 0")
	}

	return nil
}

// Helper functions for network classification
func (n Network) IsEVM() bool {
	return n == NetworkPolygon || n == NetworkPolygonAmoy || n == NetworkBaseSepolia || n == NetworkBase
}

func (n Network) IsSolana() bool {
	return n == NetworkSolanaMainnet || n == NetworkSolanaDevnet
}

func (n Network) IsCosmos() bool {
	return n == NetworkCosmosHub || n == NetworkCosmosTestnet || n == NetworkCosmosLocal
}

func (n Network) IsTestnet() bool {
	return n == NetworkPolygonAmoy || n == NetworkBaseSepolia || n == NetworkSolanaDevnet || n == NetworkCosmosTestnet
}

func (n Network) String() string {
	return string(n)
}
