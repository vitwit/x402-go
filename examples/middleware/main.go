// Package main demonstrates a resource server that uses x402-go's HTTP middleware
// to gate access behind an on-chain payment.
//
// The middleware verifies (and optionally settles) the Payment-Signature header
// before the protected handler is invoked. The verified payer address is available
// via x402.PayerFromContext.
//
// Environment variables:
//
//	EVM_RPC_URL      Ethereum JSON-RPC endpoint
//	FACILITATOR_KEY  0x-prefixed private key (required for SettleOnVerify: true)
//	PAY_TO           Address that receives payments
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/vitwit/x402-go"
	"github.com/vitwit/x402-go/networks/evm"
)

func main() {
	logger := slog.Default()

	evmProvider, err := evm.New(evm.Config{
		Networks: []string{evm.NetworkBaseSepolia},
		RPCEndpoints: map[string]string{
			evm.NetworkBaseSepolia: env("EVM_RPC_URL", "https://sepolia.base.org"),
		},
		PrivateKeyHex: env("FACILITATOR_KEY", ""),
		Logger:        logger,
	})
	if err != nil {
		logger.Error("failed to create EVM provider", "err", err)
		os.Exit(1)
	}

	x := x402.New(x402.Config{Logger: logger})
	x.RegisterNetworkProvider(evmProvider)

	paymentOptions := []x402.PaymentOption{
		{
			Scheme:            x402.SchemeExact,
			Network:           evm.NetworkBaseSepolia,
			Amount:            "1000000", // 1 USDC (6 decimals)
			Asset:             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
			PayTo:             env("PAY_TO", "0x0000000000000000000000000000000000000000"),
			MaxTimeoutSeconds: 300,
		},
	}

	mux := http.NewServeMux()

	// Unprotected route
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Free content. Try GET /premium.")
	})

	// Protected route: payment required
	mux.Handle("GET /premium", x.Handler(x402.HandlerConfig{
		Accepts: paymentOptions,
		Resource: &x402.Resource{
			URL:         "/premium",
			Description: "Premium data endpoint",
			MimeType:    "application/json",
		},
		SettleOnVerify: true,
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payer := x402.PayerFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"message":"access granted","payer":%q}`, payer)
	})))

	logger.Info("resource server listening", "addr", ":9090")
	if err := http.ListenAndServe(":9090", mux); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
