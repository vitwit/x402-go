package types

import "strings"

// Standard CAIP-2 Identifiers
const (
	NetworkEthereum       = "eip155:1"
	NetworkSepolia        = "eip155:11155111"
	NetworkBase           = "eip155:8453"
	NetworkBaseSepolia    = "eip155:84532"
	NetworkPolygon        = "eip155:137"
	NetworkPolygonAmoy    = "eip155:80002"
	NetworkSolanaMainnet  = "solana:mainnet"
	NetworkSolanaDevnet   = "solana:devnet"
)

// LegacyToCAIP2 maps common legacy network names to their CAIP-2 equivalent.
var LegacyToCAIP2 = map[string]string{
	"ethereum":       NetworkEthereum,
	"sepolia":        NetworkSepolia,
	"base":           NetworkBase,
	"base-sepolia":   NetworkBaseSepolia,
	"polygon":        NetworkPolygon,
	"polygon-amoy":   NetworkPolygonAmoy,
	"solana":         NetworkSolanaMainnet,
	"solana-mainnet": NetworkSolanaMainnet,
	"solana-devnet":  NetworkSolanaDevnet,
}

// NormalizeNetwork converts a legacy network name or a CAIP-2 string to a canonical CAIP-2 ID.
func NormalizeNetwork(network string) string {
	lower := strings.ToLower(network)
	if standardized, ok := LegacyToCAIP2[lower]; ok {
		return standardized
	}
	// If it already looks like CAIP-2 (contains a colon), return as is
	if strings.Contains(network, ":") {
		return network
	}
	return network
}
