package cosmos

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/std"
	txn "github.com/cosmos/cosmos-sdk/types/tx"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/vitwit/x402-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Verifier verifies Cosmos bank-send payment transactions.
// It uses gRPC Simulate to confirm the transaction is valid and would succeed.
type Verifier struct {
	networks   []string
	grpcDialer func(target string) (*grpc.ClientConn, error)
	grpcURLs   map[string]string // CAIP-2 -> gRPC endpoint
	txConfig   txConfigProvider
}

// txConfigProvider builds a TxDecoder from the Cosmos SDK codec.
type txConfigProvider struct {
	cdc codec.Codec
}

func newTxConfigProvider() txConfigProvider {
	registry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(registry)
	banktypes.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	return txConfigProvider{cdc: cdc}
}

func (t txConfigProvider) TxConfig() txn.ServiceClient {
	return nil // satisfied by callers via gRPC
}

func NewVerifier(networks []string) *Verifier {
	if networks == nil {
		networks = DefaultNetworks()
	}
	return &Verifier{
		networks:   networks,
		grpcURLs:   make(map[string]string),
		txConfig:   newTxConfigProvider(),
		grpcDialer: defaultGRPCDialer,
	}
}

func defaultGRPCDialer(target string) (*grpc.ClientConn, error) {
	return grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
}

func (v *Verifier) Networks() []string { return v.networks }
func (v *Verifier) Schemes() []x402.Scheme {
	return []x402.Scheme{x402.SchemeExact, x402.SchemeUpto}
}

func (v *Verifier) Verify(ctx context.Context, req x402.VerifyRequest) (x402.VerifyResult, error) {
	var cosmosPayload x402.CosmosPayload
	if err := json.Unmarshal(req.PaymentPayload.Payload, &cosmosPayload); err != nil {
		return x402.VerifyResult{}, fmt.Errorf("unmarshal cosmos payload: %w", err)
	}

	auth := cosmosPayload.Authorization

	// Expiry check
	if time.Now().Unix() >= auth.TimeoutAt {
		return x402.VerifyResult{Error: "payment authorization expired"}, nil
	}

	// Amount check
	required, ok := new(big.Int).SetString(req.PaymentOption.Amount, 10)
	if !ok {
		return x402.VerifyResult{}, fmt.Errorf("invalid amount")
	}
	paid, ok := new(big.Int).SetString(auth.Amount, 10)
	if !ok {
		return x402.VerifyResult{}, fmt.Errorf("invalid payment amount")
	}
	switch req.PaymentPayload.Accepted.Scheme {
	case x402.SchemeExact:
		if paid.Cmp(required) != 0 {
			return x402.VerifyResult{
				Error: fmt.Sprintf("payment amount %s does not equal required %s", paid, required),
			}, nil
		}
	default: // upto
		if paid.Cmp(required) < 0 {
			return x402.VerifyResult{
				Error: fmt.Sprintf("payment amount %s below required %s", paid, required),
			}, nil
		}
	}

	// Recipient check
	if !strings.EqualFold(auth.To, req.PaymentOption.PayTo) {
		return x402.VerifyResult{Error: "recipient mismatch"}, nil
	}

	txRawBytes, err := base64.StdEncoding.DecodeString(cosmosPayload.SignedTx)
	if err != nil {
		return x402.VerifyResult{}, fmt.Errorf("decode signed tx: %w", err)
	}

	// Decode tx using SDK TxConfig
	registry := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(registry)
	banktypes.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	txConfig := authtx.NewTxConfig(cdc, authtx.DefaultSignModes)

	tx, err := txConfig.TxDecoder()(txRawBytes)
	if err != nil {
		return x402.VerifyResult{Error: fmt.Sprintf("tx decode failed: %v", err)}, nil
	}

	// Validate MsgSend content
	msgs := tx.GetMsgs()
	if len(msgs) == 0 {
		return x402.VerifyResult{Error: "no messages in tx"}, nil
	}
	msgSend, ok := msgs[0].(*banktypes.MsgSend)
	if !ok {
		return x402.VerifyResult{Error: "unexpected message type"}, nil
	}
	if !strings.EqualFold(msgSend.ToAddress, auth.To) {
		return x402.VerifyResult{Error: "recipient mismatch"}, nil
	}
	sender := msgSend.FromAddress

	// Check denom and amount in MsgSend
	for _, coin := range msgSend.Amount {
		if strings.EqualFold(coin.Denom, auth.Denom) {
			coinAmt := coin.Amount.BigInt()
			amountOK := false
			switch req.PaymentPayload.Accepted.Scheme {
			case x402.SchemeExact:
				amountOK = coinAmt.Cmp(required) == 0
			default: // upto
				amountOK = coinAmt.Cmp(required) >= 0
			}
			if amountOK {
				// gRPC Simulate to confirm the tx would succeed
				if grpcURL := v.grpcURLs[req.PaymentPayload.Accepted.Network]; grpcURL != "" {
					if err := simulateTx(ctx, v.grpcDialer, grpcURL, txRawBytes); err != nil {
						return x402.VerifyResult{Error: err.Error()}, nil
					}
				}
				return x402.VerifyResult{Valid: true, Payer: sender}, nil
			}
		}
	}

	return x402.VerifyResult{Error: "token not found or insufficient amount"}, nil
}

// simulateTx calls the gRPC Simulate endpoint to dry-run the transaction.
func simulateTx(ctx context.Context, dialer func(string) (*grpc.ClientConn, error), grpcURL string, txBytes []byte) error {
	conn, err := dialer("localhost:9090")
	if err != nil {
		return fmt.Errorf("grpc dial: %w", err)
	}
	defer conn.Close()

	txClient := txn.NewServiceClient(conn)
	_, err = txClient.Simulate(ctx, &txn.SimulateRequest{TxBytes: txBytes})
	if err != nil {
		return fmt.Errorf("simulate failed: %w", err)
	}
	return nil
}
