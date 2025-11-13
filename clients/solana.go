package clients

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	binary "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/shopspring/decimal"
	x402types "github.com/vitwit/x402/types"
)

// SolanaClient provides minimal Solana functionality
type SolanaClient struct {
	network x402types.Network
	rpcURL  string
	client  *rpc.Client
}

var _ Client = (*SolanaClient)(nil)

// NewSolanaClient creates a minimal Solana client
func NewSolanaClient(network x402types.Network, rpcURL string) (*SolanaClient, error) {
	return &SolanaClient{
		network: network,
		rpcURL:  rpcURL,
		client:  rpc.New(rpcURL),
	}, nil
}

// VerifyPayment verifies Solana transaction from x402 VerifyRequest
func (c *SolanaClient) VerifyPayment(
	ctx context.Context,
	payload *x402types.VerifyRequest,
) (*x402types.VerificationResult, error) {

	data, err := base64.StdEncoding.DecodeString(payload.PaymentHeader)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	var header x402types.SolanaPaymentPayload
	if err := json.Unmarshal(data, &header); err != nil {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("invalid payment header: %v", err),
		}, nil
	}

	txBytes, err := base64.StdEncoding.DecodeString(header.Payment.TxBase64)
	if err != nil {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("invalid tx base64: %v", err),
		}, nil
	}

	dec := binary.NewBinDecoder(txBytes)
	tx, err := solana.TransactionFromDecoder(dec)
	if err != nil {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("failed to decode transaction: %v", err),
		}, nil
	}

	for _, inst := range tx.Message.Instructions {

		prog := tx.Message.AccountKeys[inst.ProgramIDIndex]
		if prog.Equals(solana.SystemProgramID) {
			// Build account metas from the instruction
			accountMetas := make([]*solana.AccountMeta, len(inst.Accounts))
			for i, accIdx := range inst.Accounts {
				pub := tx.Message.AccountKeys[accIdx]
				writable, err := tx.Message.IsWritable(pub)
				if err != nil {
					return &x402types.VerificationResult{
						IsValid:       false,
						InvalidReason: fmt.Sprintf("failed to decode transaction: %v", err),
					}, nil
				}

				accountMetas[i] = &solana.AccountMeta{
					PublicKey:  pub,
					IsSigner:   tx.Message.IsSigner(pub),
					IsWritable: writable,
				}
			}

			sysInst, err := system.DecodeInstruction(accountMetas, inst.Data)
			if err == nil {
				if transfer, ok := sysInst.Impl.(*system.Transfer); ok {
					from := accountMetas[0].PublicKey
					to := accountMetas[1].PublicKey

					if to.Equals(solana.MustPublicKeyFromBase58(payload.PaymentRequirements.PayTo)) {
						amount := decimal.NewFromInt(int64(*transfer.Lamports))
						reqAmt, _ := decimal.NewFromString(payload.PaymentRequirements.MaxAmountRequired)
						if amount.GreaterThanOrEqual(reqAmt) {
							return &x402types.VerificationResult{
								IsValid:       true,
								Amount:        &amount,
								Token:         "SOL",
								Recipient:     to.String(),
								Sender:        from.String(),
								Confirmations: 1,
							}, nil
						} else {
							// TODO: return amount not enough error
						}
					}
				}
			} else {
				// TODO: handle decode instruction error
			}
		}
	}

	return &x402types.VerificationResult{
		IsValid:       false,
		InvalidReason: "no valid SOL transfer found",
	}, nil
}

// SettlePayment broadcasts the signed Solana transaction
func (s *SolanaClient) SettlePayment(
	ctx context.Context,
	payload *x402types.VerifyRequest,
) (*x402types.SettlementResult, error) {

	data, err := base64.StdEncoding.DecodeString(payload.PaymentHeader)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	var header x402types.SolanaPaymentPayload
	if err := json.Unmarshal([]byte(data), &header); err != nil {
		return &x402types.SettlementResult{
			Success: false,
			Error:   fmt.Sprintf("invalid payment header: %v", err),
		}, nil
	}

	txBytes, err := base64.StdEncoding.DecodeString(header.Payment.TxBase64)
	if err != nil {
		return &x402types.SettlementResult{
			Success: false,
			Error:   fmt.Sprintf("invalid tx base64: %v", err),
		}, nil
	}

	tx, err := solana.TransactionFromDecoder(binary.NewBinDecoder(txBytes))
	if err != nil {
		return &x402types.SettlementResult{
			Success: false,
			Error:   fmt.Sprintf("tx decode failed: %v", err),
		}, nil
	}

	sig, err := s.client.SendTransaction(ctx, tx)
	if err != nil {
		return &x402types.SettlementResult{
			Success: false,
			Error:   fmt.Sprintf("broadcast failed: %v", err),
		}, nil
	}

	// Poll for confirmation
	for i := 0; i < 5; i++ {
		time.Sleep(3 * time.Second)
		status, err := s.client.GetSignatureStatuses(ctx, false, sig)
		if err == nil && len(status.Value) > 0 && status.Value[0] != nil && status.Value[0].ConfirmationStatus == rpc.ConfirmationStatusFinalized {
			return &x402types.SettlementResult{
				Success:   true,
				TxHash:    sig.String(),
				NetworkId: payload.PaymentRequirements.Network,
				Extra: x402types.ExtraData{
					"slot":   status.Value[0].Slot,
					"status": status.Value[0].ConfirmationStatus,
				},
			}, nil
		}
	}

	return &x402types.SettlementResult{
		Success: false,
		TxHash:  sig.String(),
		Error:   "transaction not confirmed after retries",
	}, nil
}

func (s *SolanaClient) GetNetwork() x402types.Network { return s.network }

func (s *SolanaClient) Close() {}
