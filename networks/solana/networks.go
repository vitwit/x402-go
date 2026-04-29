// Package solana implements x402 verification and settlement for Solana
// using SPL token transfers via partially-signed transactions.
package solana

// Known CAIP-2 network identifiers for Solana.
const (
	NetworkMainnet = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
	NetworkDevnet  = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	NetworkTestnet = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"
)

// DefaultNetworks returns the default Solana networks.
func DefaultNetworks() []string {
	return []string{NetworkMainnet, NetworkDevnet}
}

// RPCFromNetwork returns the default public RPC URL for a network.
func RPCFromNetwork(network string) string {
	m := map[string]string{
		NetworkMainnet: "https://api.mainnet-beta.solana.com",
		NetworkDevnet:  "https://api.devnet.solana.com",
		NetworkTestnet: "https://api.testnet.solana.com",
	}
	if u, ok := m[network]; ok {
		return u
	}
	return ""
}
