package clients

import (
	"context"

	x402types "github.com/vitwit/x402/types"
)

type Client interface {
	VerifyPayment(ctx context.Context, payload *x402types.VerifyRequest) (*x402types.VerificationResult, error)
	SettlePayment(ctx context.Context, payload *x402types.VerifyRequest) (*x402types.SettlementResult, error)
	GetNetwork() string
	Close()
}
