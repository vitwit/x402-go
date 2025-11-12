# X402 Go Library

A complete Go implementation of the x402 payment protocol for multi-chain payment verification and settlement.

## Overview

The x402 Go library provides a comprehensive solution for building payment facilitators that support multiple blockchain networks including Ethereum Virtual Machine (EVM) chains, Solana, and Cosmos SDK-based networks.

### Key Features

- **Multi-Chain Support**: EVM (Polygon, Base), Solana, Cosmos
- **Payment Verification**: Verify on-chain transactions against payment requirements
- **Payment Settlement**: Create, sign, and broadcast settlement transactions
- **Batch Operations**: Process multiple payments concurrently
- **Type Safety**: Full Go type safety with comprehensive validation
- **High Performance**: Optimized for high-throughput payment processing
- **Extensible**: Easy to add support for new networks and token standards

### Supported Networks

- **EVM Networks**:
  - Polygon (`polygon`)
  - Polygon Amoy Testnet (`polygon-amoy`)
  - Base (`base`)
  - Base Sepolia Testnet (`base-sepolia`)

- **Solana Networks**:
  - Mainnet (`solana-mainnet`)
  - Devnet (`solana-devnet`)

- **Cosmos Networks**:
  - Cosmos Hub (`cosmoshub-4`)
  - Theta Testnet (`theta-testnet-001`)

### Supported Token Standards

- **ERC20**: Ethereum-compatible token standard
- **SPL**: Solana Program Library tokens
- **CW20**: CosmWasm token standard
- **Native**: Native blockchain tokens (ETH, SOL, ATOM, etc.)

## Installation

```bash
go get github.com/vitwit/x402
```

## Quick Start

```go
package main

import (
    "context"
    "log"
    
    x402 "github.com/vitwit/x402"
    "github.com/vitwit/x402/types"
)

func main() {
    // Initialize the x402 client
    client := x402.NewWithDefaults()
    defer client.Close()
    
    // Add network support
    config := types.ClientConfig{
        Network: types.NetworkPolygonAmoy,
        RPCUrl:  "https://rpc-amoy.polygon.technology/",
        ChainID: "80002",
    }
    
    if err := client.AddNetwork(types.NetworkPolygonAmoy, config); err != nil {
        log.Fatal("Failed to add network:", err)
    }
    
    // Create payment payload and requirements
    payload, requirements := x402.CreateTestPayment()
    
    // Verify payment
    result, err := client.VerifyWithObjects(context.Background(), payload, requirements)
    if err != nil {
        log.Fatal("Verification failed:", err)
    }
    
    log.Printf("Payment valid: %v", result.Valid)
}
```

## Core Concepts

### Payment Payload

A payment payload contains the actual transaction data that needs to be verified:

```go
payload := &types.PaymentPayload{
    Network:   types.NetworkPolygonAmoy,
    Amount:    "1.5",
    Token:     "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", // USDC
    Recipient: "0x742d35Cc6634C0532925a3b8D098f69DB22B6b8B",
    Sender:    "0x8ba1f109551bD432803012645Hac136c22ABB6",
    Timestamp: time.Now(),
    Memo:      "Payment for API access",
    EVM: &types.EVMPaymentData{
        TransactionHash: "0x1234...5678",
        BlockNumber:     12345678,
    },
}
```

### Payment Requirements

Payment requirements specify what constitutes a valid payment:

```go
requirements := &types.PaymentRequirements{
    X402Version: types.X402Version1,
    Scheme:      types.SchemeExact,
    Network:     types.NetworkPolygonAmoy,
    Token: types.TokenInfo{
        Standard: types.TokenStandardERC20,
        Address:  "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
        Symbol:   "USDC",
        Decimals: 6,
    },
    Amount: &types.Amount{
        Value: decimal.NewFromFloat(1.5),
    },
    Recipient: "0x742d35Cc6634C0532925a3b8D098f69DB22B6b8B",
}
```

## Usage Examples

### Basic Payment Verification

```go
// Quick verification (no blockchain queries)
quickResult, err := client.QuickVerify(payload, requirements)
if err != nil {
    log.Fatal(err)
}

// Full verification (with blockchain queries)
fullResult, err := client.VerifyWithObjects(ctx, payload, requirements)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Payment valid: %v", fullResult.Valid)
```

### Payment Settlement

```go
// Create settlement request
request := &types.SettlementRequest{
    PaymentPayload:      *payload,
    PaymentRequirements: *requirements,
    PrivateKey:          privateKey,
    Options: types.SettlementOptions{
        Priority:      types.PriorityMedium,
        Confirmations: 1,
    },
}

// Settle payment
result, err := client.SettleWithObjects(ctx, request)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Settlement successful: %v, TxHash: %s", result.Success, result.TransactionHash)
```

### Batch Operations

```go
// Verify multiple payments concurrently
results, err := client.BatchVerify(ctx, payloads, requirements)
if err != nil {
    log.Fatal(err)
}

for i, result := range results {
    fmt.Printf("Payment %d valid: %v", i, result.Valid)
}

// Settle multiple payments concurrently
settlementResults, err := client.BatchSettle(ctx, requests)
if err != nil {
    log.Fatal(err)
}
```

### Multi-Chain Support

```go
// Add multiple networks
networks := []struct {
    network types.Network
    rpcUrl  string
    chainID string
}{
    {types.NetworkPolygonAmoy, "https://rpc-amoy.polygon.technology/", "80002"},
    {types.NetworkSolanaDevnet, "https://api.devnet.solana.com", "devnet"},
    {types.NetworkBaseSepolia, "https://sepolia.base.org/", "84532"},
}

for _, net := range networks {
    config := types.ClientConfig{
        Network: net.network,
        RPCUrl:  net.rpcUrl,
        ChainID: net.chainID,
    }
    
    if err := client.AddNetwork(net.network, config); err != nil {
        log.Printf("Failed to add %s: %v", net.network, err)
    }
}

// Check supported networks
supportedNetworks := client.GetSupportedNetworks()
fmt.Printf("Supported networks: %v", supportedNetworks)
```

## Architecture

The library is organized into several key components:

### Core Types (`types/`)
- Defines all data structures and interfaces
- Network and token type definitions
- Error handling types

### Clients (`clients/`)
- Network-specific blockchain clients
- EVM client for Ethereum-compatible chains
- Solana client for Solana network
- Cosmos client for Cosmos SDK chains

### Verification (`verification/`)
- Payment verification logic
- Multi-chain verification routing
- Batch verification support

### Settlement (`settlement/`)
- Payment settlement logic
- Transaction creation and broadcasting
- Multi-chain settlement routing

### Utilities (`utils/`)
- Cryptographic functions
- Validation helpers
- JSON parsing and serialization

## Advanced Features

### Custom Network Configuration

```go
config := &types.X402Config{
    DefaultTimeout:    60 * time.Second,
    RetryCount:        5,
    EnableMetrics:     true,
    LogLevel:          "debug",
    Clients: map[types.Network]types.ClientConfig{
        types.NetworkPolygon: {
            RPCUrl:     "https://polygon-rpc.com",
            WSUrl:      "wss://polygon-ws.com",
            Timeout:    30 * time.Second,
            RetryCount: 3,
        },
    },
}

client := x402.New(config)
```

### Gas Estimation

```go
// Estimate gas costs before settlement
gasLimit, err := client.EstimateSettlementGas(ctx, settlementRequest)
if err != nil {
    log.Fatal("Gas estimation failed:", err)
}

fmt.Printf("Estimated gas: %d", gasLimit)
```

### Flexible Amount Schemes

```go
// Exact amount
exactAmount := &types.Amount{
    Value: decimal.NewFromFloat(1.5),
}

// Range amount
rangeAmount := &types.Amount{
    Min: decimal.NewFromFloat(1.0),
    Max: decimal.NewFromFloat(2.0),
}

// Any amount (for donations, tips, etc.)
anyAmount := &types.Amount{
    Currency: "USDC",
}
```

## Error Handling

The library provides comprehensive error handling with specific error codes:

```go
if err != nil {
    if x402Err, ok := err.(*types.X402Error); ok {
        switch x402Err.Code {
        case types.ErrInvalidPayload:
            // Handle invalid payload
        case types.ErrUnsupportedNetwork:
            // Handle unsupported network
        case types.ErrVerificationFailed:
            // Handle verification failure
        }
    }
}
```

## Testing

Run the test suite:

```bash
go test ./...
```

Run with coverage:

```bash
go test -cover ./...
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## Performance Considerations

### High-Throughput Operations

- Use batch operations for multiple payments
- Configure appropriate timeouts for your use case
- Consider connection pooling for high-volume scenarios

### Resource Management

- Always call `client.Close()` when done
- Set appropriate context timeouts
- Monitor memory usage with large batches

### Network Optimization

- Use WebSocket connections where available
- Configure retry policies based on network reliability
- Consider regional RPC endpoints for better latency

## Security Best Practices

### Private Key Management

- Never hardcode private keys
- Use secure key management systems
- Rotate keys regularly

### Input Validation

- Always validate input parameters
- Use the built-in validation functions
- Implement additional business logic validation

### Network Security

- Use HTTPS/WSS for all connections
- Validate SSL certificates
- Implement rate limiting

## Troubleshooting

### Common Issues

1. **Network Connection Failures**
   - Check RPC endpoint availability
   - Verify network configuration
   - Check firewall settings

2. **Transaction Verification Failures**
   - Ensure transaction is confirmed
   - Check block confirmations
   - Verify network matches

3. **Settlement Failures**
   - Verify private key format
   - Check account balance
   - Ensure proper gas estimation

### Debug Mode

Enable debug logging:

```go
config := &types.X402Config{
    LogLevel: "debug",
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- GitHub Issues: Report bugs and request features
- Documentation: Check the docs for detailed API reference
- Examples: See the `examples/` directory for usage examples

## Roadmap

- [ ] Additional EVM chains support
- [ ] More Cosmos SDK chains
- [ ] Enhanced gas optimization
- [ ] Metrics and monitoring integration
- [ ] GraphQL API support
- [ ] Mobile SDK support