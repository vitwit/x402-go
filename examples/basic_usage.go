package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/shopspring/decimal"
	x402 "github.com/vitwit/x402"
	"github.com/vitwit/x402/types"
	"github.com/vitwit/x402/utils"
)

func main() {
	// Initialize the x402 library
	x402Client := x402.NewWithDefaults()
	defer x402Client.Close()

	// Add network support
	if err := addNetworkSupport(x402Client); err != nil {
		log.Fatal("Failed to configure networks:", err)
	}

	// Example 1: Basic payment verification
	fmt.Println("=== Example 1: Payment Verification ===")
	if err := exampleVerification(x402Client); err != nil {
		log.Printf("Verification example failed: %v", err)
	}

	// Example 2: Payment settlement
	fmt.Println("\n=== Example 2: Payment Settlement ===")
	if err := exampleSettlement(x402Client); err != nil {
		log.Printf("Settlement example failed: %v", err)
	}

	// Example 3: Batch operations
	fmt.Println("\n=== Example 3: Batch Operations ===")
	if err := exampleBatchOperations(x402Client); err != nil {
		log.Printf("Batch operations example failed: %v", err)
	}

	// Example 4: Multi-chain support
	fmt.Println("\n=== Example 4: Multi-chain Support ===")
	if err := exampleMultiChain(x402Client); err != nil {
		log.Printf("Multi-chain example failed: %v", err)
	}

	// Show supported networks
	fmt.Println("\n=== Supported Networks ===")
	networks := x402Client.GetSupportedNetworks()
	for _, network := range networks {
		fmt.Printf("- %s\n", network)
	}

	// Show version info
	fmt.Println("\n=== Version Information ===")
	version := x402.GetVersion()
	for key, value := range version {
		fmt.Printf("%s: %v\n", key, value)
	}
}

// addNetworkSupport configures network clients
func addNetworkSupport(client *x402.X402) error {
	// Add Polygon Amoy testnet support
	polygonConfig := types.ClientConfig{
		Network: types.NetworkPolygonAmoy,
		RPCUrl:  "https://rpc-amoy.polygon.technology/",
		ChainID: "80002",
	}
	if err := client.AddNetwork(types.NetworkPolygonAmoy, polygonConfig); err != nil {
		return fmt.Errorf("failed to add Polygon Amoy: %w", err)
	}

	// Add Base Sepolia testnet support
	baseConfig := types.ClientConfig{
		Network: types.NetworkBaseSepolia,
		RPCUrl:  "https://sepolia.base.org/",
		ChainID: "84532",
	}
	if err := client.AddNetwork(types.NetworkBaseSepolia, baseConfig); err != nil {
		return fmt.Errorf("failed to add Base Sepolia: %w", err)
	}

	// Add Solana Devnet support
	solanaConfig := types.ClientConfig{
		Network: types.NetworkSolanaDevnet,
		RPCUrl:  "https://api.devnet.solana.com",
		WSUrl:   "wss://api.devnet.solana.com/",
		ChainID: "devnet",
	}
	if err := client.AddNetwork(types.NetworkSolanaDevnet, solanaConfig); err != nil {
		return fmt.Errorf("failed to add Solana Devnet: %w", err)
	}

	return nil
}

// exampleVerification demonstrates payment verification
func exampleVerification(client *x402.X402) error {
	ctx := context.Background()

	// Create sample payment payload for EVM (Polygon)
	payload := &types.PaymentPayload{
		Network:   types.NetworkPolygonAmoy,
		Amount:    "1.5",
		Token:     "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", // USDC on Polygon
		Recipient: "0x742d35Cc6634C0532925a3b8D098f69DB22B6b8B",
		Sender:    "0x8ba1f109551bD432803012645Hac136c22ABB6",
		Timestamp: time.Now(),
		Memo:      "Payment for API access",
		EVM: &types.EVMPaymentData{
			TransactionHash: "0x1234567890123456789012345678901234567890123456789012345678901234",
			BlockNumber:     12345678,
			GasUsed:         21000,
		},
	}

	// Create payment requirements
	value, _ := decimal.NewFromString("1.5")
	requirements := &types.PaymentRequirements{
		X402Version: types.X402Version1,
		Scheme:      types.SchemeExact,
		Network:     types.NetworkPolygonAmoy,
		Token: types.TokenInfo{
			Standard: types.TokenStandardERC20,
			Address:  "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
			Symbol:   "USDC",
			Decimals: 6,
			Name:     "USD Coin",
		},
		Amount: &types.Amount{
			Value: &value,
		},
		Recipient: "0x742d35Cc6634C0532925a3b8D098f69DB22B6b8B",
	}

	// Perform quick verification (no blockchain queries)
	quickResult, err := client.QuickVerify(payload, requirements)
	if err != nil {
		return fmt.Errorf("quick verification failed: %w", err)
	}

	fmt.Printf("Quick Verification Result: Valid=%v, Error=%s\n", 
		quickResult.Valid, quickResult.Error)

	// Perform full verification (with blockchain queries)
	// Note: This would fail in the example since we don't have a real transaction
	fullResult, err := client.VerifyWithObjects(ctx, payload, requirements)
	if err != nil {
		return fmt.Errorf("full verification failed: %w", err)
	}

	fmt.Printf("Full Verification Result: Valid=%v, Error=%s\n", 
		fullResult.Valid, fullResult.Error)

	return nil
}

// exampleSettlement demonstrates payment settlement
func exampleSettlement(client *x402.X402) error {
	ctx := context.Background()

	// Create settlement request
	payload := &types.PaymentPayload{
		Network:   types.NetworkSolanaDevnet,
		Amount:    "0.1",
		Token:     "SOL", // Native SOL
		Recipient: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
		Sender:    "GjJyKtw3BgkMvXTpVR1CZzDp6XZQkBpYDaFr4Bd6nKvT",
		Timestamp: time.Now(),
		Memo:      "Settlement payment",
		Solana: &types.SolanaPaymentData{
			Signature: "5j8ym7LohPhHJZvVw2gvFuRmD8EPtZM5ZpW9JfPPYHYzqxJZ9VrSKJjm8bWQvJJfvw",
			Slot:      100000,
		},
	}

	value, _ := decimal.NewFromString("0.1")
	requirements := &types.PaymentRequirements{
		X402Version: types.X402Version1,
		Scheme:      types.SchemeExact,
		Network:     types.NetworkSolanaDevnet,
		Token: types.TokenInfo{
			Standard: types.TokenStandardNative,
			Symbol:   "SOL",
			Decimals: 9,
			Name:     "Solana",
		},
		Amount: &types.Amount{
			Value: &value,
		},
		Recipient: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
	}

	// Create settlement request
	settlementOptions := &types.SettlementOptions{
		Priority:      types.PriorityMedium,
		Confirmations: 1,
	}

	request := &types.SettlementRequest{
		PaymentPayload:      *payload,
		PaymentRequirements: *requirements,
		PrivateKey:          "your_private_key_here", // In practice, load from secure storage
		Options:             *settlementOptions,
	}

	// Estimate gas costs
	gasLimit, err := client.EstimateSettlementGas(ctx, request)
	if err != nil {
		return fmt.Errorf("gas estimation failed: %w", err)
	}

	fmt.Printf("Estimated gas limit: %d\n", gasLimit)

	// Perform settlement (would fail without real private key)
	result, err := client.SettleWithObjects(ctx, request)
	if err != nil {
		return fmt.Errorf("settlement failed: %w", err)
	}

	fmt.Printf("Settlement Result: Success=%v, TxHash=%s, Error=%s\n",
		result.Success, result.TransactionHash, result.Error)

	return nil
}

// exampleBatchOperations demonstrates batch verification and settlement
func exampleBatchOperations(client *x402.X402) error {
	ctx := context.Background()

	// Create multiple payment payloads
	payloads := []*types.PaymentPayload{
		createSampleEVMPayload("1.0", "Payment 1"),
		createSampleEVMPayload("2.5", "Payment 2"),
		createSampleSolanaPayload("0.5", "Payment 3"),
	}

	// Create corresponding requirements
	requirements := []*types.PaymentRequirements{
		createSampleEVMRequirements("1.0"),
		createSampleEVMRequirements("2.5"),
		createSampleSolanaRequirements("0.5"),
	}

	// Convert to JSON for batch verification
	payloadBytes := make([][]byte, len(payloads))
	requirementBytes := make([][]byte, len(requirements))
	
	for i, payload := range payloads {
		payloadData, err := utils.SerializePaymentPayload(payload)
		if err != nil {
			return fmt.Errorf("failed to serialize payload %d: %w", i, err)
		}
		payloadBytes[i] = payloadData
		
		requirementData, err := utils.SerializePaymentRequirements(requirements[i])
		if err != nil {
			return fmt.Errorf("failed to serialize requirements %d: %w", i, err)
		}
		requirementBytes[i] = requirementData
	}

	// Perform batch verification
	results, err := client.BatchVerify(ctx, payloadBytes, requirementBytes)
	if err != nil {
		return fmt.Errorf("batch verification failed: %w", err)
	}

	fmt.Printf("Batch Verification Results:\n")
	for i, result := range results {
		fmt.Printf("  Payment %d: Valid=%v, Error=%s\n", 
			i+1, result.Valid, result.Error)
	}

	// Create settlement requests for batch settlement
	requests := make([]*types.SettlementRequest, len(payloads))
	for i := range payloads {
		requests[i] = &types.SettlementRequest{
			PaymentPayload:      *payloads[i],
			PaymentRequirements: *requirements[i],
			PrivateKey:          "your_private_key_here",
			Options: types.SettlementOptions{
				Priority:      types.PriorityMedium,
				Confirmations: 1,
			},
		}
	}

	// Perform batch settlement (would fail without real private keys)
	settlementResults, err := client.BatchSettle(ctx, requests)
	if err != nil {
		return fmt.Errorf("batch settlement failed: %w", err)
	}

	fmt.Printf("Batch Settlement Results:\n")
	for i, result := range settlementResults {
		fmt.Printf("  Payment %d: Success=%v, TxHash=%s, Error=%s\n",
			i+1, result.Success, result.TransactionHash, result.Error)
	}

	return nil
}

// exampleMultiChain demonstrates multi-chain capabilities
func exampleMultiChain(client *x402.X402) error {
	networks := client.GetSupportedNetworks()
	fmt.Printf("Configured networks: %v\n", networks)

	// Check network support
	testNetworks := []types.Network{
		types.NetworkPolygonAmoy,
		types.NetworkBaseSepolia,
		types.NetworkSolanaDevnet,
		types.NetworkCosmosTestnet,
	}

	for _, network := range testNetworks {
		supported := client.IsNetworkSupported(network)
		fmt.Printf("Network %s supported: %v\n", network, supported)
	}

	// Get supported payment kinds
	paymentKinds := client.GetSupportedPaymentKinds()
	fmt.Printf("Supported payment kinds:\n")
	for _, kind := range paymentKinds {
		fmt.Printf("  - Network: %s, Scheme: %s, Version: %d\n",
			kind.Network, kind.Scheme, kind.X402Version)
	}

	return nil
}

// Helper functions for creating sample data

func createSampleEVMPayload(amount, memo string) *types.PaymentPayload {
	return &types.PaymentPayload{
		Network:   types.NetworkPolygonAmoy,
		Amount:    amount,
		Token:     "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
		Recipient: "0x742d35Cc6634C0532925a3b8D098f69DB22B6b8B",
		Sender:    "0x8ba1f109551bD432803012645Hac136c22ABB6",
		Timestamp: time.Now(),
		Memo:      memo,
		EVM: &types.EVMPaymentData{
			TransactionHash: "0x1234567890123456789012345678901234567890123456789012345678901234",
			BlockNumber:     12345678,
		},
	}
}

func createSampleEVMRequirements(amount string) *types.PaymentRequirements {
	value, _ := decimal.NewFromString(amount)
	return &types.PaymentRequirements{
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
			Value: &value,
		},
		Recipient: "0x742d35Cc6634C0532925a3b8D098f69DB22B6b8B",
	}
}

func createSampleSolanaPayload(amount, memo string) *types.PaymentPayload {
	return &types.PaymentPayload{
		Network:   types.NetworkSolanaDevnet,
		Amount:    amount,
		Token:     "SOL",
		Recipient: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
		Sender:    "GjJyKtw3BgkMvXTpVR1CZzDp6XZQkBpYDaFr4Bd6nKvT",
		Timestamp: time.Now(),
		Memo:      memo,
		Solana: &types.SolanaPaymentData{
			Signature: "5j8ym7LohPhHJZvVw2gvFuRmD8EPtZM5ZpW9JfPPYHYzqxJZ9VrSKJjm8bWQvJJfvw",
			Slot:      100000,
		},
	}
}

func createSampleSolanaRequirements(amount string) *types.PaymentRequirements {
	value, _ := decimal.NewFromString(amount)
	return &types.PaymentRequirements{
		X402Version: types.X402Version1,
		Scheme:      types.SchemeExact,
		Network:     types.NetworkSolanaDevnet,
		Token: types.TokenInfo{
			Standard: types.TokenStandardNative,
			Symbol:   "SOL",
			Decimals: 9,
		},
		Amount: &types.Amount{
			Value: &value,
		},
		Recipient: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
	}
}