# How to Use x402-go

This guide walks through building a **facilitator service** on top of x402-go, and separately a **resource server** that uses the payment middleware.

> x402-go is a **library**, not a server. Your application owns the HTTP server, private keys, and process lifecycle. Networks and chain configuration come entirely from your code — nothing is hardcoded.

---

## 1. Install

```sh
go get github.com/vitwit/x402-go
```

---

## 2. Create an X402 Instance

```go
import (
    "log/slog"
    "github.com/vitwit/x402-go"
)

x := x402.New(x402.Config{
    Logger: slog.Default(), // any slog.Logger, or x402.NopLogger{} for silence
})
```

---

## 3. Register Network Providers

Network providers are created by your application with the RPC endpoints and credentials you supply. Register as many as you need.

### EVM (Base, Ethereum, Polygon, …)

```go
import "github.com/vitwit/x402-go/networks/evm"

provider, err := evm.New(evm.Config{
    Networks: []string{evm.NetworkBaseSepolia},
    RPCEndpoints: map[string]string{
        evm.NetworkBaseSepolia: "https://sepolia.base.org",
    },
    PrivateKeyHex: os.Getenv("FACILITATOR_PRIVATE_KEY"), // 0x-prefixed hex; omit for verify-only
})
if err != nil {
    log.Fatal(err)
}
x.RegisterNetworkProvider(provider)
```

The EVM provider supports three asset transfer methods, selected by the client via `extra.assetTransferMethod` in the `PaymentOption`:

| Method | Description | `extra.assetTransferMethod` |
|---|---|---|
| EIP-3009 | `transferWithAuthorization` — native to USDC and similar tokens | `"eip3009"` (default) |
| Permit2 | `permitWitnessTransferFrom` — universal fallback for any ERC-20 | `"permit2"` |
| ERC-7710 | Smart account delegation via `redeemDelegations` | `"erc7710"` |

Permit2 requires the payer to have approved the canonical Permit2 contract (`0x000000000022D473030F116dDEE9F6B43aC78BA3`) on the token. Settlement for Permit2 calls the canonical `x402ExactPermit2Proxy` contract (`0x402085c248EeA27D92E8b30b2C58ed07f9E20001`).

Add a custom or unlisted EVM chain at runtime:

```go
provider.AddNetwork("eip155:1337", "http://localhost:8545", x402.ChainInfo{
    Network:     "eip155:1337",
    Name:        "Local Anvil",
    Type:        x402.ChainTypeEVM,
    NativeToken: "ETH",
    Decimals:    18,
})
```

### Cosmos (Cosmos Hub, Osmosis, Neutron, …)

```go
import "github.com/vitwit/x402-go/networks/cosmos"

provider := cosmos.New(cosmos.Config{
    Networks: []string{cosmos.NetworkCosmosHub},
    GRPCEndpoints: map[string]string{
        cosmos.NetworkCosmosHub: "cosmos-grpc.publicnode.com:443",
    },
    RESTEndpoints: map[string]string{
        cosmos.NetworkCosmosHub: "https://cosmos-rest.publicnode.com",
    },
})
x.RegisterNetworkProvider(provider)
```

### Solana (Mainnet, Devnet)

```go
import (
    "github.com/vitwit/x402-go/networks/solana"
    solanago "github.com/gagliardetto/solana-go"
)

privKey := solanago.MustPrivateKeyFromBase58(os.Getenv("SOLANA_PRIVATE_KEY"))

provider := solana.New(solana.Config{
    Networks: []string{solana.NetworkDevnet},
    RPCEndpoints: map[string]string{
        solana.NetworkDevnet: "https://api.devnet.solana.com",
    },
    PrivateKey: privKey, // omit for verify-only
})
x.RegisterNetworkProvider(provider)
```

The Solana settler includes a **duplicate-settlement cache**: if the same base64 transaction payload is submitted to `/settle` more than once within 120 seconds, the second call is rejected with `"duplicate_settlement"`. This closes the race-condition double-spend window described in the x402 Solana spec.

---

## 4. Build a Facilitator Service

A facilitator exposes three endpoints: `GET /supported`, `POST /verify`, `POST /settle`.

```go
mux := http.NewServeMux()

// List supported networks and schemes
mux.HandleFunc("GET /supported", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(x.Supported())
})

// Verify a payment header
mux.HandleFunc("POST /verify", func(w http.ResponseWriter, r *http.Request) {
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
})

// Settle a verified payment
mux.HandleFunc("POST /settle", func(w http.ResponseWriter, r *http.Request) {
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
})

log.Fatal(http.ListenAndServe(":8080", mux))
```

---

## 5. Embed Payment Middleware (Resource Server)

For resource servers that handle their own verification and settlement inline — without calling an external facilitator — use `Handler`:

```go
paymentOptions := []x402.PaymentOption{
    {
        Scheme:            x402.SchemeExact,
        Network:           evm.NetworkBaseSepolia,
        Amount:            "1000000", // 1 USDC (6 decimals)
        Asset:             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        PayTo:             "0xYourReceivingAddress",
        MaxTimeoutSeconds: 300,
    },
}

protected := x.Handler(x402.HandlerConfig{
    Accepts:        paymentOptions,
    SettleOnVerify: true, // false if you settle via a separate facilitator
}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    payer := x402.PayerFromContext(r.Context()) // verified payer address
    fmt.Fprintf(w, "paid by %s", payer)
}))

http.Handle("/api/premium", protected)
```

When `SettleOnVerify: false`, the middleware only verifies the signature — settlement is left to an external facilitator that the resource server calls separately.

To accept Permit2 payments alongside EIP-3009, add a second `PaymentOption` with `Extra` set:

```go
import "encoding/json"

paymentOptions := []x402.PaymentOption{
    {
        Scheme:  x402.SchemeExact,
        Network: evm.NetworkBaseSepolia,
        Amount:  "1000000",
        Asset:   "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        PayTo:   "0xYourReceivingAddress",
        Extra:   json.RawMessage(`{"assetTransferMethod":"eip3009","name":"USDC","version":"2"}`),
        MaxTimeoutSeconds: 300,
    },
    {
        Scheme:  x402.SchemeExact,
        Network: evm.NetworkBaseSepolia,
        Amount:  "1000000",
        Asset:   "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        PayTo:   "0xYourReceivingAddress",
        Extra:   json.RawMessage(`{"assetTransferMethod":"permit2"}`),
        MaxTimeoutSeconds: 300,
    },
}
```

---

## 6. Payment Wire Format

The `PaymentOption` the server advertises in the `402` response uses `"amount"` for the required payment amount (atomic units):

```json
{
  "scheme":            "exact",
  "network":           "eip155:84532",
  "amount":            "1000000",
  "asset":             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  "payTo":             "0xYourReceivingAddress",
  "maxTimeoutSeconds": 300,
  "extra": { "assetTransferMethod": "eip3009", "name": "USDC", "version": "2" }
}
```

The client's `Payment-Signature` header is a base64-encoded `PaymentPayloadV2`:

```json
{
  "x402Version": 2,
  "resource": { "url": "/api/premium", "description": "...", "mimeType": "application/json" },
  "accepted": {
    "scheme": "exact",
    "network": "eip155:84532",
    "amount": "1000000",
    "asset":  "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "payTo":  "0xYourReceivingAddress",
    "maxTimeoutSeconds": 300,
    "extra": { "assetTransferMethod": "eip3009", "name": "USDC", "version": "2" }
  },
  "payload": {
    "signature": "0x...",
    "authorization": {
      "from":        "0xClientAddress",
      "to":          "0xYourReceivingAddress",
      "value":       "1000000",
      "validAfter":  "1740672089",
      "validBefore": "1740672389",
      "nonce":       "0xabc..."
    }
  }
}
```

The routing key is `accepted.network` + `accepted.scheme` — both must match a registered provider.

---

## 7. Query Chain State

```go
// List all registered chains
chains := x.ListChains(ctx)

// Get static metadata for a specific network
info, err := x.ChainInfo(ctx, evm.NetworkBaseSepolia)

// Get the latest block
block, err := x.LatestBlock(ctx, evm.NetworkBaseSepolia)

// Check if a network is registered
ok := x.IsNetworkSupported(evm.NetworkBaseSepolia)
```

---

## 8. Decode Payment Headers Manually

```go
// Decode the Payment-Signature header value sent by the client
payload, err := x402.ParsePaymentPayload(r.Header.Get(x402.HeaderPaymentSignature))
// payload.Accepted.Network, payload.Accepted.Scheme, payload.Payload, …

// Decode the Payment-Required header value
pr, err := x402.ParsePaymentRequired(r.Header.Get(x402.HeaderPaymentRequired))
```

---

## 9. Supported Response Format

`x.Supported()` returns `[]x402.SupportedCapability`:

```json
[
  { "network": "eip155:84532",                            "scheme": "exact" },
  { "network": "eip155:84532",                            "scheme": "upto"  },
  { "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "scheme": "exact" },
  { "network": "cosmos:cosmoshub-4",                      "scheme": "exact" }
]
```
