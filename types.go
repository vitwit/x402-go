package x402

import (
	"encoding/json"
	"time"
)

// ChainType classifies a blockchain's execution environment.
type ChainType string

const (
	ChainTypeEVM    ChainType = "evm"
	ChainTypeSolana ChainType = "solana"
	ChainTypeCosmos ChainType = "cosmos"
)

// ChainInfo holds static, human-readable metadata about a chain.
type ChainInfo struct {
	Network     string    // CAIP-2 identifier (e.g. "eip155:8453")
	Name        string    // human-readable name (e.g. "Base")
	Type        ChainType
	NativeToken string // symbol of the gas/fee token (e.g. "ETH", "SOL", "ATOM")
	Decimals    int    // decimals of the native token
}

// BlockInfo holds information about a single block.
type BlockInfo struct {
	Network   string
	Height    int64
	Hash      string
	Timestamp time.Time
	// TxCount is -1 when the chain/RPC does not expose it cheaply.
	TxCount int
}

const (
	VersionV1 = 1
	VersionV2 = 2
)

type Scheme string

const (
	SchemeExact Scheme = "exact"
	SchemeUpto  Scheme = "upto"
)

// HTTP header names per x402 spec
const (
	HeaderPaymentRequired  = "Payment-Required"
	HeaderPaymentSignature = "Payment-Signature"
	HeaderPaymentResponse  = "Payment-Response"
)

// Resource describes the endpoint being accessed.
type Resource struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// PaymentOption is a single accepted payment method in a 402 response.
// The JSON field name "amount" matches the x402-foundation spec for EVM and Solana.
type PaymentOption struct {
	Scheme            Scheme          `json:"scheme"`
	Network           string          `json:"network"`           // CAIP-2 (e.g. "eip155:8453")
	Amount            string          `json:"amount"`            // atomic units (EVM/Solana: "amount", Cosmos: same)
	Asset             string          `json:"asset"`             // token address or mint
	PayTo             string          `json:"payTo"`
	MaxTimeoutSeconds int             `json:"maxTimeoutSeconds"`
	Description       string          `json:"description,omitempty"`
	MimeType          string          `json:"mimeType,omitempty"`
	Extra             json.RawMessage `json:"extra,omitempty"`
}

// PaymentRequiredV2 is the body/header sent with HTTP 402 in protocol v2.
type PaymentRequiredV2 struct {
	X402Version int             `json:"x402Version"`
	Error       string          `json:"error,omitempty"`
	Resource    *Resource       `json:"resource,omitempty"`
	Accepts     []PaymentOption `json:"accepts"`
}

// PaymentRequiredV1 is the legacy v1 structure.
type PaymentRequiredV1 struct {
	X402Version int             `json:"x402Version"`
	Accepts     []PaymentOption `json:"accepts"`
}

// --- EVM (EIP-3009 / Permit2 / ERC-7710) ---

// EVMAuthorization holds the EIP-712 typed data fields for EIP-3009.
// ValidAfter and ValidBefore are Unix timestamps encoded as JSON strings per the x402 spec.
type EVMAuthorization struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`  // unix timestamp as string, e.g. "1740672089"
	ValidBefore string `json:"validBefore"` // unix timestamp as string, e.g. "1740672154"
	Nonce       string `json:"nonce"`       // 0x-prefixed 32-byte hex
}

// Permit2TokenPermissions holds the token and amount for a Permit2 transfer.
type Permit2TokenPermissions struct {
	Token  string `json:"token"`  // ERC-20 token address
	Amount string `json:"amount"` // token amount in atomic units
}

// Permit2Witness is the x402-specific witness data embedded in Permit2 signatures.
type Permit2Witness struct {
	To         string `json:"to"`         // payment recipient address
	ValidAfter string `json:"validAfter"` // unix timestamp as string
}

// Permit2Authorization holds all parameters for a Permit2 permitWitnessTransferFrom call.
type Permit2Authorization struct {
	Permitted Permit2TokenPermissions `json:"permitted"`
	From      string                 `json:"from"`     // token owner / payer
	Spender   string                 `json:"spender"`  // must equal x402ExactPermit2Proxy address
	Nonce     string                 `json:"nonce"`    // uint256 as decimal string
	Deadline  string                 `json:"deadline"` // unix timestamp as string
	Witness   Permit2Witness         `json:"witness"`
}

// EVMPayload is the network-specific payload for EVM chains.
// Which fields are populated depends on extra.assetTransferMethod:
//   - "" or "eip3009": Signature + Authorization
//   - "permit2":       Signature + Permit2Authorization
//   - "erc7710":       DelegationManager + PermissionContext + Delegator
type EVMPayload struct {
	// EIP-3009 fields
	Signature     string            `json:"signature,omitempty"`
	Authorization *EVMAuthorization `json:"authorization,omitempty"`
	// Permit2 fields
	Permit2Authorization *Permit2Authorization `json:"permit2Authorization,omitempty"`
	// ERC-7710 fields
	DelegationManager string `json:"delegationManager,omitempty"`
	PermissionContext  string `json:"permissionContext,omitempty"`
	Delegator         string `json:"delegator,omitempty"`
}

// --- Solana (SPL token transfer) ---

// SolanaPayload is the network-specific payload for Solana.
// Transaction is a base64-encoded partially-signed Solana transaction.
type SolanaPayload struct {
	Transaction string `json:"transaction"`
}

// --- Cosmos (bank send) ---

// CosmosAuthorization holds the fields for a Cosmos bank send authorization.
type CosmosAuthorization struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Amount    string `json:"amount"` // atomic units
	Denom     string `json:"denom"`
	TimeoutAt int64  `json:"timeoutAt"` // unix timestamp
}

// CosmosPayload is the network-specific payload for Cosmos-based chains.
// SignedTx is a base64-encoded signed Cosmos transaction (protobuf TxRaw).
type CosmosPayload struct {
	Signature     string              `json:"signature"`
	Authorization CosmosAuthorization `json:"authorization"`
	SignedTx      string              `json:"signedTx"`
}

// --- Payment header sent by the client ---

// PaymentPayloadV2 is decoded from the Payment-Signature header (v2).
// The structure matches the x402-foundation spec: the full accepted PaymentOption
// is embedded under the "accepted" key, and "resource" carries the endpoint context.
type PaymentPayloadV2 struct {
	X402Version int             `json:"x402Version"`
	Resource    *Resource       `json:"resource,omitempty"`
	Accepted    PaymentOption   `json:"accepted"`
	Payload     json.RawMessage `json:"payload"` // EVMPayload | SolanaPayload | CosmosPayload
}

// PaymentPayloadV1 is the legacy v1 client payment header.
type PaymentPayloadV1 struct {
	X402Version int             `json:"x402Version"`
	Scheme      Scheme          `json:"scheme"`
	Network     string          `json:"network"`
	Payload     json.RawMessage `json:"payload"`
}

// --- Settlement result sent in the response header ---

// PaymentResponse is base64-encoded into the Payment-Response header.
type PaymentResponse struct {
	Status          string `json:"status"`                    // "success" | "failed"
	TransactionHash string `json:"transactionHash,omitempty"` // on success
	Network         string `json:"network,omitempty"`         // on success
	Payer           string `json:"payer,omitempty"`
	Error           string `json:"error,omitempty"` // on failure
}

// VerifyRequest is passed to a Verifier.
type VerifyRequest struct {
	PaymentPayload PaymentPayloadV2
	PaymentOption  PaymentOption
}

// VerifyResult is returned by a Verifier.
type VerifyResult struct {
	Valid bool
	Payer string
	Error string
}

// SettleRequest is passed to a Settler.
type SettleRequest struct {
	PaymentPayload PaymentPayloadV2
	PaymentOption  PaymentOption
}

// SettleResult is returned by a Settler.
type SettleResult struct {
	Success         bool
	TransactionHash string
	Network         string
	Payer           string
	Error           string
}

// SupportedCapability describes a single (network, scheme) pair the server can handle.
type SupportedCapability struct {
	Network string
	Scheme  Scheme
}
