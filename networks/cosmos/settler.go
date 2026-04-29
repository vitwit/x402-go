package cosmos

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	txn "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/vitwit/x402-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	confirmationTimeout  = 15 * time.Second
	confirmationInterval = 3 * time.Second
)

// SettlerConfig holds gRPC endpoints for each Cosmos network.
type SettlerConfig struct {
	// GRPCEndpoints maps CAIP-2 network ID → Cosmos gRPC address (host:port).
	GRPCEndpoints map[string]string
	// RESTEndpoints is kept for GetLatestBlock fallback in the provider.
	RESTEndpoints map[string]string
}

// Settler broadcasts a pre-signed Cosmos transaction via gRPC.
type Settler struct {
	networks   []string
	cfg        SettlerConfig
	grpcDialer func(target string) (*grpc.ClientConn, error)
}

func NewSettler(networks []string, cfg SettlerConfig) *Settler {
	if networks == nil {
		networks = DefaultNetworks()
	}
	return &Settler{
		networks: networks,
		cfg:      cfg,
		grpcDialer: func(target string) (*grpc.ClientConn, error) {
			return grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
		},
	}
}

func (s *Settler) Networks() []string { return s.networks }
func (s *Settler) Schemes() []x402.Scheme {
	return []x402.Scheme{x402.SchemeExact, x402.SchemeUpto}
}

func (s *Settler) Settle(ctx context.Context, req x402.SettleRequest) (x402.SettleResult, error) {
	var cosmosPayload x402.CosmosPayload
	if err := json.Unmarshal(req.PaymentPayload.Payload, &cosmosPayload); err != nil {
		return x402.SettleResult{}, fmt.Errorf("unmarshal cosmos payload: %w", err)
	}

	network := req.PaymentPayload.Accepted.Network
	grpcURL := s.cfg.GRPCEndpoints[network]
	if grpcURL == "" {
		return x402.SettleResult{Error: "no gRPC endpoint for " + network}, nil
	}

	txRawBytes, err := base64.StdEncoding.DecodeString(cosmosPayload.SignedTx)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("decode signed tx: %w", err)
	}

	conn, err := s.grpcDialer("localhost:9090")
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("grpc dial: %w", err)
	}
	defer conn.Close()

	txClient := txn.NewServiceClient(conn)

	broadcastResp, err := txClient.BroadcastTx(ctx, &txn.BroadcastTxRequest{
		TxBytes: txRawBytes,
		Mode:    txn.BroadcastMode_BROADCAST_MODE_SYNC,
	})
	if err != nil {
		return x402.SettleResult{Error: err.Error()}, nil
	}
	if broadcastResp.TxResponse.Code != 0 {
		return x402.SettleResult{Error: broadcastResp.TxResponse.RawLog}, nil
	}

	txHash := broadcastResp.TxResponse.TxHash
	sender := cosmosPayload.Authorization.From

	// Poll until the tx is committed on-chain (up to confirmationTimeout)
	deadline := time.Now().Add(confirmationTimeout)
	for time.Now().Before(deadline) {
		txResult, err := txClient.GetTx(ctx, &txn.GetTxRequest{Hash: txHash})
		if err == nil && txResult.TxResponse != nil && txResult.TxResponse.Height > 0 {
			if txResult.TxResponse.Code == 0 {
				return x402.SettleResult{
					Success:         true,
					TransactionHash: txHash,
					Network:         network,
					Payer:           sender,
				}, nil
			}
			return x402.SettleResult{
				Error:           txResult.TxResponse.RawLog,
				TransactionHash: txHash,
				Network:         network,
				Payer:           sender,
			}, nil
		}
		time.Sleep(confirmationInterval)
	}

	return x402.SettleResult{
		Error:           "timeout waiting for confirmation",
		TransactionHash: txHash,
		Network:         network,
		Payer:           sender,
	}, nil
}
