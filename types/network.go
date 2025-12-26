package types

// ChainFamily classifies a network into a blockchain family.
type ChainFamily string

const (
	ChainEVM    ChainFamily = "evm"
	ChainSolana ChainFamily = "solana"
	ChainCosmos ChainFamily = "cosmos"
)

// ChainPaymentPayload is an internal normalized representation
// of a decoded chain-specific payment payload.
type ChainPaymentPayload interface {
	Payer() string
	Recipient() string
	Amount() string
	TxBytes() []byte
}

// PaymentContext wraps immutable x402 spec types
// for internal processing.
type PaymentContext struct {
	Version      X402Version
	Requirements PaymentRequirements
	Payload      PaymentPayload

	Network     string
	ChainFamily ChainFamily

	DecodedPayload ChainPaymentPayload
}

type NetworkCapability struct {
	Network     string
	X402Version int
	Scheme      string
	ChainFamily ChainFamily
}
