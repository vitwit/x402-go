# x402-go

A Go library implementing the [x402 payment protocol](https://x402.org) for multi-chain payment verification and settlement.

x402-go is a **library**. Your application (the facilitator) owns the HTTP server, key management, and lifecycle. This library provides the verification, settlement, and HTTP middleware logic — wired together through a clean provider interface.

## Installation

```sh
go get github.com/vitwit/x402-go
```

## Supported Networks

| Chain family | Networks (built-in)                                  |
|---|---|
| EVM          | Base, Base Sepolia, Ethereum, Polygon, Polygon Amoy  |
| Solana       | Mainnet, Devnet, Testnet                             |
| Cosmos       | Cosmos Hub, Osmosis, Neutron, Celestia               |

Custom networks can be registered at runtime via `AddNetwork` on each provider.

## Quick Start

```go
import (
    "log/slog"
    "github.com/vitwit/x402-go"
    "github.com/vitwit/x402-go/networks/evm"
)

evmProvider, err := evm.New(evm.Config{
    Networks:      []string{evm.NetworkBaseSepolia},
    RPCEndpoints:  map[string]string{evm.NetworkBaseSepolia: "https://sepolia.base.org"},
    PrivateKeyHex: os.Getenv("FACILITATOR_KEY"), // required for settlement
})
if err != nil {
    log.Fatal(err)
}

x := x402.New(x402.Config{Logger: slog.Default()})
x.RegisterNetworkProvider(evmProvider)

// Verify a payment (facilitator /verify endpoint)
result, err := x.Verify(ctx, req)

// Settle a verified payment (facilitator /settle endpoint)
result, err := x.Settle(ctx, req)

// Embed payment enforcement in an HTTP route (resource server)
http.Handle("/api/resource", x.Handler(x402.HandlerConfig{
    Accepts: []x402.PaymentOption{{
        Scheme:            x402.SchemeExact,
        Network:           evm.NetworkBaseSepolia,
        Amount:            "1000000", // 1 USDC (6 decimals)
        Asset:             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        PayTo:             "0xYourAddress",
        MaxTimeoutSeconds: 300,
    }},
    SettleOnVerify: true,
}, myHandler))
```

For a complete walkthrough see [HOW_TO_USE.md](HOW_TO_USE.md) and the [examples/](examples/) directory.

## Architecture

```
x402/
├── x402.go          — X402: top-level entry point for facilitators
├── interfaces.go    — Verifier, Settler, ChainProvider, NetworkProvider interfaces
├── types.go         — Protocol types (PaymentOption, VerifyRequest, SettleRequest, …)
├── registry.go      — Internal routing table: (network, scheme) → provider
├── handler.go       — HTTP payment middleware (PaymentMiddleware)
├── codec.go         — Header encode/decode helpers
└── networks/
    ├── evm/         — EVM provider: EIP-3009, Permit2, ERC-7710
    ├── solana/      — Solana provider: SPL TransferChecked
    └── cosmos/      — Cosmos provider: bank MsgSend
```

## Implementing a Custom Provider

Any struct that satisfies `x402.NetworkProvider` can be registered:

```go
type NetworkProvider interface {
    Networks() []string
    Schemes()  []x402.Scheme

    Verify(ctx context.Context, req x402.VerifyRequest) (x402.VerifyResult, error)
    Settle(ctx context.Context, req x402.SettleRequest) (x402.SettleResult, error)

    ChainInfo(ctx context.Context, network string) (x402.ChainInfo, error)
    LatestBlock(ctx context.Context, network string) (x402.BlockInfo, error)
    BlockByHeight(ctx context.Context, network string, height int64) (x402.BlockInfo, error)
}
```

Register it with:

```go
x.RegisterNetworkProvider(myProvider)
```

If you only need verification (no on-chain settlement), implement `x402.Verifier` and register with `RegisterVerifier`.

## Protocol Specifications

- [EVM — EIP-3009 / Permit2 / ERC-7710](specs/evm.md)
- [Solana — SPL TransferChecked](specs/solana.md)
- [Cosmos — bank MsgSend](specs/cosmos.md)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## License

MIT — see [LICENSE](LICENSE).
