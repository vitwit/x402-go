package types

import (
	"encoding/json"
	"math/big"
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
	NetworkPolygon      Network = "polygon"
	NetworkPolygonAmoy  Network = "polygon-amoy" // testnet
	NetworkBaseSepolia  Network = "base-sepolia" // testnet
	NetworkBase         Network = "base"

	// Solana Networks
	NetworkSolanaMainnet Network = "solana-mainnet"
	NetworkSolanaDevnet  Network = "solana-devnet" // testnet

	// Cosmos Networks
	NetworkCosmosHub    Network = "cosmoshub-4"
	NetworkCosmosTestnet Network = "theta-testnet-001"
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

// PaymentRequirements defines what payment is required
type PaymentRequirements struct {
	X402Version X402Version   `json:"x402Version" validate:"required"`
	Scheme      PaymentScheme `json:"scheme" validate:"required"`
	Network     Network       `json:"network" validate:"required"`
	Token       TokenInfo     `json:"token" validate:"required"`
	Amount      *Amount       `json:"amount" validate:"required"`
	Recipient   string        `json:"recipient" validate:"required"`
	Memo        string        `json:"memo,omitempty"`
	Deadline    *time.Time    `json:"deadline,omitempty"`
	Extra       ExtraData     `json:"extra,omitempty"`
}

// TokenInfo contains information about the payment token
type TokenInfo struct {
	Standard      TokenStandard `json:"standard" validate:"required"`
	Address       string        `json:"address,omitempty"` // Contract address for tokens, empty for native
	Symbol        string        `json:"symbol" validate:"required"`
	Decimals      int           `json:"decimals" validate:"required"`
	Name          string        `json:"name,omitempty"`
	ChainID       string        `json:"chainId,omitempty"`
	CoingeckoID   string        `json:"coingeckoId,omitempty"`
	LogoURL       string        `json:"logoUrl,omitempty"`
	Verified      bool          `json:"verified,omitempty"`
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

// PaymentPayload represents the actual payment data submitted
type PaymentPayload struct {
	// Common fields
	Network   Network    `json:"network" validate:"required"`
	Amount    string     `json:"amount" validate:"required"`
	Token     string     `json:"token" validate:"required"`
	Recipient string     `json:"recipient" validate:"required"`
	Sender    string     `json:"sender" validate:"required"`
	Timestamp time.Time  `json:"timestamp" validate:"required"`
	Memo      string     `json:"memo,omitempty"`
	
	// Network-specific data
	EVM    *EVMPaymentData    `json:"evm,omitempty"`
	Solana *SolanaPaymentData `json:"solana,omitempty"`
	Cosmos *CosmosPaymentData `json:"cosmos,omitempty"`
}

// EVMPaymentData contains EVM-specific payment information
type EVMPaymentData struct {
	TransactionHash string `json:"transactionHash" validate:"required"`
	BlockNumber     uint64 `json:"blockNumber,omitempty"`
	BlockHash       string `json:"blockHash,omitempty"`
	TransactionIndex uint  `json:"transactionIndex,omitempty"`
	GasUsed         uint64 `json:"gasUsed,omitempty"`
	GasPrice        string `json:"gasPrice,omitempty"`
	Nonce           uint64 `json:"nonce,omitempty"`
	
	// EIP-712 signature data
	Signature       string          `json:"signature,omitempty"`
	TypedData       json.RawMessage `json:"typedData,omitempty"`
	
	// Contract interaction data
	ContractAddress string `json:"contractAddress,omitempty"`
	MethodID        string `json:"methodId,omitempty"`
	InputData       string `json:"inputData,omitempty"`
}

// SolanaPaymentData contains Solana-specific payment information
type SolanaPaymentData struct {
	Signature       string `json:"signature" validate:"required"`
	Slot            uint64 `json:"slot,omitempty"`
	BlockTime       int64  `json:"blockTime,omitempty"`
	ConfirmationStatus string `json:"confirmationStatus,omitempty"`
	
	// Transaction details
	FeePayer        string   `json:"feePayer,omitempty"`
	ComputeUnitsUsed uint64  `json:"computeUnitsUsed,omitempty"`
	Fee             uint64   `json:"fee,omitempty"`
	Instructions    []string `json:"instructions,omitempty"`
	
	// SPL Token specific
	TokenProgram    string `json:"tokenProgram,omitempty"`
	TokenAccount    string `json:"tokenAccount,omitempty"`
	MintAddress     string `json:"mintAddress,omitempty"`
}

// CosmosPaymentData contains Cosmos-specific payment information
type CosmosPaymentData struct {
	TxHash      string `json:"txHash" validate:"required"`
	Height      int64  `json:"height,omitempty"`
	GasUsed     int64  `json:"gasUsed,omitempty"`
	GasWanted   int64  `json:"gasWanted,omitempty"`
	
	// Transaction details
	Memo        string             `json:"memo,omitempty"`
	Fee         CosmosAmount       `json:"fee,omitempty"`
	Messages    []json.RawMessage  `json:"messages,omitempty"`
	Events      []json.RawMessage  `json:"events,omitempty"`
}

// CosmosAmount represents amounts in Cosmos SDK format
type CosmosAmount struct {
	Denom  string `json:"denom"`
	Amount string `json:"amount"`
}

// SupportedPaymentKind describes what payment types a facilitator supports
type SupportedPaymentKind struct {
	X402Version X402Version   `json:"x402Version"`
	Scheme      PaymentScheme `json:"scheme"`
	Network     Network       `json:"network"`
	Extra       ExtraData     `json:"extra,omitempty"`
}

// VerificationResult contains the result of payment verification
type VerificationResult struct {
	Valid         bool              `json:"valid"`
	Amount        *decimal.Decimal  `json:"amount,omitempty"`
	Token         string            `json:"token,omitempty"`
	Recipient     string            `json:"recipient,omitempty"`
	Sender        string            `json:"sender,omitempty"`
	Timestamp     *time.Time        `json:"timestamp,omitempty"`
	Confirmations int               `json:"confirmations,omitempty"`
	Error         string            `json:"error,omitempty"`
	Extra         ExtraData         `json:"extra,omitempty"`
}

// SettlementRequest contains data needed for settlement
type SettlementRequest struct {
	PaymentPayload      PaymentPayload      `json:"paymentPayload" validate:"required"`
	PaymentRequirements PaymentRequirements `json:"paymentRequirements" validate:"required"`
	PrivateKey          string              `json:"privateKey" validate:"required"`
	Options             SettlementOptions   `json:"options,omitempty"`
}

// SettlementOptions contains optional settlement parameters
type SettlementOptions struct {
	MaxGasPrice    *big.Int          `json:"maxGasPrice,omitempty"`
	GasLimit       *big.Int          `json:"gasLimit,omitempty"`
	Priority       PriorityLevel     `json:"priority,omitempty"`
	Deadline       *time.Time        `json:"deadline,omitempty"`
	Confirmations  int               `json:"confirmations,omitempty"`
	Extra          ExtraData         `json:"extra,omitempty"`
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
	Success         bool          `json:"success"`
	TransactionHash string        `json:"transactionHash,omitempty"`
	BlockNumber     uint64        `json:"blockNumber,omitempty"`
	Confirmations   int           `json:"confirmations,omitempty"`
	GasUsed         uint64        `json:"gasUsed,omitempty"`
	Fee             string        `json:"fee,omitempty"`
	Timestamp       time.Time     `json:"timestamp"`
	Error           string        `json:"error,omitempty"`
	Extra           ExtraData     `json:"extra,omitempty"`
}

// ClientConfig contains configuration for blockchain clients
type ClientConfig struct {
	Network     Network           `json:"network"`
	RPCUrl      string            `json:"rpcUrl"`
	WSUrl       string            `json:"wsUrl,omitempty"`
	ChainID     string            `json:"chainId,omitempty"`
	Timeout     time.Duration     `json:"timeout,omitempty"`
	RetryCount  int               `json:"retryCount,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Extra       ExtraData         `json:"extra,omitempty"`
}

// X402Config contains global configuration for the x402 library
type X402Config struct {
	DefaultTimeout    time.Duration            `json:"defaultTimeout,omitempty"`
	RetryCount        int                      `json:"retryCount,omitempty"`
	Clients           map[Network]ClientConfig `json:"clients,omitempty"`
	LogLevel          string                   `json:"logLevel,omitempty"`
	EnableMetrics     bool                     `json:"enableMetrics,omitempty"`
	Extra             ExtraData                `json:"extra,omitempty"`
}

// Error types
type X402Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
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

// Helper methods for validation
func (p *PaymentPayload) Validate() error {
	if p.Network == "" {
		return &X402Error{Code: ErrInvalidPayload, Message: "network is required"}
	}
	if p.Amount == "" {
		return &X402Error{Code: ErrInvalidPayload, Message: "amount is required"}
	}
	if p.Recipient == "" {
		return &X402Error{Code: ErrInvalidPayload, Message: "recipient is required"}
	}
	if p.Sender == "" {
		return &X402Error{Code: ErrInvalidPayload, Message: "sender is required"}
	}
	return nil
}

func (r *PaymentRequirements) Validate() error {
	if r.X402Version != X402Version1 {
		return &X402Error{Code: ErrInvalidRequirements, Message: "unsupported x402 version"}
	}
	if r.Network == "" {
		return &X402Error{Code: ErrInvalidRequirements, Message: "network is required"}
	}
	if r.Recipient == "" {
		return &X402Error{Code: ErrInvalidRequirements, Message: "recipient is required"}
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
	return n == NetworkCosmosHub || n == NetworkCosmosTestnet
}

func (n Network) IsTestnet() bool {
	return n == NetworkPolygonAmoy || n == NetworkBaseSepolia || n == NetworkSolanaDevnet || n == NetworkCosmosTestnet
}