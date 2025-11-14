package clients

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/std"
	txn "github.com/cosmos/cosmos-sdk/types/tx"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/shopspring/decimal"
	"github.com/vitwit/x402/types"
	x402types "github.com/vitwit/x402/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// CosmosClient provides basic Cosmos functionality
type CosmosClient struct {
	network       x402types.Network
	rpcURL        string
	TxConfig      client.TxConfig
	AcceptedDenom string
	grpc          *grpc.ClientConn
}

var _ Client = (*CosmosClient)(nil)

// NewCosmosClient creates a minimal Cosmos client
func NewCosmosClient(network x402types.Network, rpcURL string, grpcUrl string, acceptedDenom string) (*CosmosClient, error) {
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(interfaceRegistry)
	banktypes.RegisterInterfaces(interfaceRegistry)

	// Create codec
	marshaler := codec.NewProtoCodec(interfaceRegistry)

	// Build TxConfig (used for decoding/encoding transactions)
	txConfig := authtx.NewTxConfig(marshaler, authtx.DefaultSignModes)

	conn, err := grpc.NewClient(grpcUrl, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("gRPC connection failed: %v", err)
	}

	return &CosmosClient{
		network:       network,
		rpcURL:        rpcURL,
		TxConfig:      txConfig,
		AcceptedDenom: acceptedDenom,
		grpc:          conn,
	}, nil
}

// VerifyPayment for Cosmos - simplified implementation
func (c *CosmosClient) VerifyPayment(
	ctx context.Context,
	payload *x402types.VerifyRequest,
) (*x402types.VerificationResult, error) {

	if c.grpc == nil {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: "RPC client not initialized",
		}, nil
	}

	data, err := base64.StdEncoding.DecodeString(payload.PaymentPayload.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	var header types.CosmosPaymentPayload
	if err := json.Unmarshal([]byte(data), &header); err != nil {
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

	// Decode raw tx
	tx, err := c.TxConfig.TxDecoder()(txBytes)
	if err != nil {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("tx decode failed: %v", err),
		}, nil
	}

	msgs := tx.GetMsgs()
	if len(msgs) == 0 {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "no messages in tx"}, nil
	}

	msgSend, ok := msgs[0].(*banktypes.MsgSend)
	if !ok {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "unexpected message type"}, nil
	}

	// Verify recipient matches
	if msgSend.ToAddress != payload.PaymentRequirements.PayTo {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "recipient mismatch"}, nil
	}

	// Check amount and denom
	for _, amt := range msgSend.Amount {
		if amt.Denom == c.AcceptedDenom {
			sentAmt, _ := decimal.NewFromString(amt.Amount.String())
			reqAmt, _ := decimal.NewFromString(payload.PaymentRequirements.MaxAmountRequired)

			if sentAmt.LessThanOrEqual(reqAmt) {
				return &x402types.VerificationResult{IsValid: false, InvalidReason: "insufficient payment"}, nil
			}

			txClient := txn.NewServiceClient(c.grpc)
			_, err := txClient.Simulate(ctx, &txn.SimulateRequest{
				TxBytes: txBytes,
			})

			if err != nil {
				return &x402types.VerificationResult{
					IsValid:       false,
					InvalidReason: err.Error(),
				}, nil
			}

			return &x402types.VerificationResult{
				IsValid:       true,
				Amount:        &sentAmt,
				Token:         amt.Denom,
				Recipient:     msgSend.ToAddress,
				Sender:        msgSend.FromAddress,
				Confirmations: 1,
			}, nil
		}
	}

	return &x402types.VerificationResult{IsValid: false, InvalidReason: "token not found in tx"}, nil
}

func (c *CosmosClient) SettlePayment(
	ctx context.Context,
	payload *x402types.VerifyRequest,
) (*x402types.SettlementResult, error) {

	if _, err := c.VerifyPayment(ctx, payload); err != nil {
		return nil, err
	}

	if c.grpc == nil {
		return &x402types.SettlementResult{
			Success: false,
			Error:   "RPC client not initialized",
		}, nil
	}

	data, err := base64.StdEncoding.DecodeString(payload.PaymentPayload.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	var header types.CosmosPaymentPayload
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

	txClient := txn.NewServiceClient(c.grpc)
	broadcastResult, err := txClient.BroadcastTx(ctx, &txn.BroadcastTxRequest{
		TxBytes: txBytes,
		Mode:    txn.BroadcastMode_BROADCAST_MODE_SYNC,
	})

	if err != nil {
		return &x402types.SettlementResult{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &x402types.SettlementResult{
		Success: broadcastResult.TxResponse.Code == 0,
		TxHash:  broadcastResult.TxResponse.TxHash,
		Extra: x402types.ExtraData{
			"code":      broadcastResult.TxResponse.Code,
			"codespace": broadcastResult.TxResponse.Codespace,
			"log":       broadcastResult.TxResponse.RawLog,
		},
	}, nil
}

func (c *CosmosClient) WaitForConfirmation(ctx context.Context, txHash string, confirmations int) (*x402types.SettlementResult, error) {
	return &x402types.SettlementResult{
		Success: true,
		TxHash:  txHash,
	}, nil
}

func (c *CosmosClient) GetNetwork() x402types.Network { return c.network }

func (c *CosmosClient) Close() {}
