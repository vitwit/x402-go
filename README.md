# X402 Go Library

A complete Go implementation of the x402 payment protocol for multi-chain payment verification and settlement.

## Overview

The x402 Go library provides a comprehensive solution for building payment facilitators that support multiple blockchain networks including Ethereum Virtual Machine (EVM) chains, Solana, and Cosmos SDK-based networks.

### Key Features

- **Multi-Chain Support**: EVM (Polygon, Base), Solana, Cosmos
- **Payment Verification**: Verify on-chain transactions against payment requirements
- **Payment Settlement**: Create, sign, and broadcast settlement transactions
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
  - Osmosis Mainnet (`osmosis-1`)

### Supported Token Standards

- **ERC20**: Ethereum-compatible token standard
- **SPL**: Solana Program Library tokens
- **Native**: Native Cosmos blockchain tokens

## Installation

```bash
go get github.com/vitwit/x402
```

## Core Concepts

### Payment Payload

A payment payload contains the actual transaction data that needs to be verified:

```go
type PaymentPayload struct {
	// X402 payment protocol version.
	X402Version int `json:"x402Version"`

	// Payment scheme (e.g. "exact").
	Scheme string `json:"scheme"`

	// Target network (e.g. "base-testnet", "solana-devnet", etc.).
	Network string `json:"network"`

	// Base64-encoded transaction payload.
	Payload string `json:"payload"`
}

```

### Payment Requirements

Payment requirements specify what constitutes a valid payment:

```go
// PaymentRequirements defines the requirements a resource server accepts for payment.
type PaymentRequirements struct {
	// Scheme of the payment protocol to use (e.g., "exact", "stream").
	Scheme string `json:"scheme"`

	// Network of the blockchain to send payment on (e.g., "ethereum-mainnet").
	Network string `json:"network"`

	// Maximum amount required to pay for the resource in atomic units of the asset.
	// Represented as a string because Go does not support uint256.
	MaxAmountRequired string `json:"maxAmountRequired"`

	// URL of the resource to pay for.
	Resource string `json:"resource"`

	// Description of the resource being purchased.
	Description string `json:"description"`

	// MIME type of the resource response (e.g., "application/json").
	MimeType string `json:"mimeType"`

	// Output schema of the resource response, if applicable.
	OutputSchema map[string]interface{} `json:"outputSchema,omitempty"`

	// Address to which the payment must be sent.
	PayTo string `json:"payTo"`

	// Maximum time in seconds for the resource server to respond.
	MaxTimeoutSeconds int `json:"maxTimeoutSeconds"`

	// Address of the EIP-3009 compliant ERC20 contract.
	Asset string `json:"asset"`

	// Extra information about payment details specific to the scheme.
	// For the `exact` scheme on EVM, this may include fields like `name` and `version`.
	Extra map[string]interface{} `json:"extra,omitempty"`
}
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


### Utilities (`utils/`)
- Cryptographic functions
- Validation helpers
- JSON parsing and serialization


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