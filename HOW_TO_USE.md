# How to Use x402 Go Library

This guide shows **how to integrate the x402 Go library into your application** and enable
payment verification and settlement across **EVM, Solana, and Cosmos** networks.

> ⚠️ Important:
> - `x402` is a **library**, not a server
> - Your application owns the REST server, `/metrics` endpoint, and lifecycle
> - Networks are **facilitator-defined**, not hardcoded

---

## 1. Create Logger and Metrics (Application Side)

``` go
import (
	"github.com/vitwit/x402/logger"
	"github.com/vitwit/x402/metrics"
)

log := logger.NewZapLogger("info")
recorder := metrics.NewPrometheusRecorder()
```

If you don’t want observability:

``` go
log := logger.NoopLogger{}
recorder := metrics.NoopRecorder{}
```

## 2. Create x402 Instance

``` go
import (
	"github.com/vitwit/x402"
	"github.com/vitwit/x402/types"
)

cfg := &types.X402Config{
	DefaultTimeout: 30 * time.Second,
	EnableMetrics:  true,
	LogLevel:       "info",
}

x := x402.New(
	cfg,
	x402.WithLogger(log),
	x402.WithMetrics(recorder),
)
```

## 3. Add Networks

### 3.1 EVM Example(Base testnet)

``` go
evmClient, err := clients.NewEVMClient(clients.EVMConfig{
	RPCUrl:   "https://polygon-rpc.com",
	ChainID: "137",
})
if err != nil {
	panic(err)
}

x.AddEVMNetwork("polygon", evmClient)

```

### 3.2 Solana Example (Devnet)

``` go
solanaClient, err := clients.NewSolanaClient(clients.SolanaConfig{
	RPCUrl: "https://api.devnet.solana.com",
})
if err != nil {
	panic(err)
}

x.AddSolanaNetwork("solana-devnet", solanaClient)
```

### 3.3 Cosmos Example (Cosmos Hub)

```go
cosmosClient, err := clients.NewCosmosClient(clients.CosmosConfig{
	RPCUrl:  "https://rpc.cosmoshub.strange.love",
	GRPCUrl: "grpc.cosmoshub.strange.love:443",
	ChainID: "cosmoshub-4",
})
if err != nil {
	panic(err)
}

x.AddCosmosNetwork("cosmoshub-4", cosmosClient)
```

## 4. Expose `/supported` Endpoint (REST Server)

``` go
http.HandleFunc("/supported", func(w http.ResponseWriter, r *http.Request) {
	resp, _ := x.Supported()
	json.NewEncoder(w).Encode(resp)
})
```

Example Response:

``` json
{
  "kinds": [
    { "x402Version": 1, "scheme": "exact", "network": "polygon" },
    { "x402Version": 1, "scheme": "exact", "network": "solana-devnet" },
    { "x402Version": 1, "scheme": "exact", "network": "cosmoshub-4" }
  ]
}
```

## 5. Verify Payment

``` go
result, err := x.Verify(ctx, verifyRequest)
if err != nil {
	log.Error("verification failed", map[string]any{
		"error": err.Error(),
	})
}
```

## 6. Settle Payment

``` go
result, err := x.Settle(ctx, verifyRequest)
if err != nil {
	log.Error("settlement failed", map[string]any{
		"error": err.Error(),
	})
}
```

## 7. Expose Prometheus Metrics

``` go
import "github.com/prometheus/client_golang/prometheus/promhttp"

http.Handle("/metrics", promhttp.Handler())
http.ListenAndServe(":8080", nil)
```