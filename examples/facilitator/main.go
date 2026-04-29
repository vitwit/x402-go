// Package main demonstrates a complete x402 facilitator service built on x402-go.
//
// The facilitator exposes three endpoints:
//
//	GET  /supported  — list supported networks and schemes
//	POST /verify     — verify a payment header
//	POST /settle     — settle a verified payment on-chain
//
// Environment variables:
//
//	EVM_RPC_URL          Ethereum JSON-RPC endpoint (e.g. https://sepolia.base.org)
//	FACILITATOR_KEY      0x-prefixed private key of the facilitator wallet
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"

	solanago "github.com/gagliardetto/solana-go"
	"github.com/vitwit/x402-go"
	"github.com/vitwit/x402-go/networks/cosmos"
	"github.com/vitwit/x402-go/networks/evm"
	"github.com/vitwit/x402-go/networks/solana"
)

func main() {
	logger := slog.Default()

	x := x402.New(x402.Config{Logger: logger})

	if err := registerEVM(x); err != nil {
		logger.Error("failed to register EVM provider", "err", err)
		os.Exit(1)
	}
	registerCosmos(x)
	registerSolana(x)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /supported", handleSupported(x))
	mux.HandleFunc("POST /verify", handleVerify(x))
	mux.HandleFunc("POST /settle", handleSettle(x))

	logger.Info("facilitator listening", "addr", ":8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}

func registerEVM(x *x402.X402) error {
	rpcURL := env("EVM_RPC_URL", "https://sepolia.base.org")
	privKey := env("FACILITATOR_KEY", "")

	provider, err := evm.New(evm.Config{
		Networks:      []string{evm.NetworkBaseSepolia},
		RPCEndpoints:  map[string]string{evm.NetworkBaseSepolia: rpcURL},
		PrivateKeyHex: privKey, // empty → verify-only
		Logger:        slog.Default(),
	})
	if err != nil {
		return err
	}
	x.RegisterNetworkProvider(provider)
	return nil
}

func registerCosmos(x *x402.X402) {
	provider := cosmos.New(cosmos.Config{
		Networks: []string{cosmos.NetworkCosmosHub},
		GRPCEndpoints: map[string]string{
			cosmos.NetworkCosmosHub: env("COSMOS_GRPC", "cosmos-grpc.publicnode.com:443"),
		},
		RESTEndpoints: map[string]string{
			cosmos.NetworkCosmosHub: env("COSMOS_REST", "https://cosmos-rest.publicnode.com"),
		},
		Logger: slog.Default(),
	})
	x.RegisterNetworkProvider(provider)
}

func registerSolana(x *x402.X402) {
	cfg := solana.Config{
		Networks: []string{solana.NetworkDevnet},
		RPCEndpoints: map[string]string{
			solana.NetworkDevnet: env("SOLANA_RPC", "https://api.devnet.solana.com"),
		},
		Logger: slog.Default(),
	}
	if key := env("SOLANA_KEY", ""); key != "" {
		cfg.PrivateKey = solanago.MustPrivateKeyFromBase58(key)
	}
	x.RegisterNetworkProvider(solana.New(cfg))
}

func handleSupported(x *x402.X402) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(x.Supported())
	}
}

func handleVerify(x *x402.X402) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req x402.VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		result, err := x.Verify(r.Context(), req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func handleSettle(x *x402.X402) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req x402.SettleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		result, err := x.Settle(r.Context(), req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
