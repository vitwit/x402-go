// Package evm implements x402 verification and settlement for EVM-compatible
// chains using EIP-3009 TransferWithAuthorization.
package evm

// Known CAIP-2 network identifiers for EVM chains.
const (
	NetworkBaseMainnet    = "eip155:8453"
	NetworkBaseSepolia    = "eip155:84532"
	NetworkEthMainnet     = "eip155:1"
	NetworkPolygonMainnet = "eip155:137"
	NetworkPolygonAmoy    = "eip155:80002"
)

// DefaultNetworks returns the set of EVM networks supported by default.
func DefaultNetworks() []string {
	return []string{
		NetworkBaseMainnet,
		NetworkBaseSepolia,
		NetworkEthMainnet,
		NetworkPolygonMainnet,
		NetworkPolygonAmoy,
	}
}

// ChainIDFromNetwork returns the integer chain ID for a CAIP-2 network string.
func ChainIDFromNetwork(network string) (int64, bool) {
	m := map[string]int64{
		NetworkBaseMainnet:    8453,
		NetworkBaseSepolia:    84532,
		NetworkEthMainnet:     1,
		NetworkPolygonMainnet: 137,
		NetworkPolygonAmoy:    80002,
	}
	id, ok := m[network]
	return id, ok
}
