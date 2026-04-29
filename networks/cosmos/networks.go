// Package cosmos implements x402 verification and settlement for Cosmos SDK
// chains using standard bank module Send transactions.
package cosmos

// Known CAIP-2 network identifiers for Cosmos chains.
const (
	NetworkCosmosHub = "cosmos:cosmoshub-4"
	NetworkOsmosis   = "cosmos:osmosis-1"
	NetworkCelestia  = "cosmos:celestia"
	NetworkNeutron   = "cosmos:neutron-1"
)

// DefaultNetworks returns the default Cosmos networks.
func DefaultNetworks() []string {
	return []string{NetworkCosmosHub, NetworkOsmosis, NetworkNeutron}
}

// RESTFromNetwork returns the default public Cosmos REST base URL for a network.
func RESTFromNetwork(network string) string {
	m := map[string]string{
		NetworkCosmosHub: "https://cosmos-rest.publicnode.com",
		NetworkOsmosis:   "https://osmosis-rest.publicnode.com",
		NetworkNeutron:   "https://neutron-rest.publicnode.com",
		NetworkCelestia:  "https://celestia-rest.publicnode.com",
	}
	return m[network]
}

// GRPCFromNetwork returns the default public gRPC address for a network.
func GRPCFromNetwork(network string) string {
	m := map[string]string{
		NetworkCosmosHub: "cosmos-grpc.publicnode.com:443",
		NetworkOsmosis:   "osmosis-grpc.publicnode.com:443",
		NetworkNeutron:   "neutron-grpc.publicnode.com:443",
		NetworkCelestia:  "celestia-grpc.publicnode.com:443",
	}
	return m[network]
}
