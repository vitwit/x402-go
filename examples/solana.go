package main

// import (
// 	"context"
// 	"fmt"
// 	"log"

// 	x402 "github.com/vitwit/x402"
// 	"github.com/vitwit/x402/types"
// )

// func main() {
// 	x402Client := x402.NewWithDefaults()
// 	defer x402Client.Close()

// 	if err := addNetworkSupport(x402Client); err != nil {
// 		log.Fatal("Failed to configure networks:", err)
// 	}

// 	x, _ := x402Client.Supported()
// 	fmt.Println(x)

// 	fmt.Println("=== Example 1: Solana Payment Verification ===")
// 	if err := exampleVerification(x402Client); err != nil {
// 		log.Printf("Verification example failed: %v", err)
// 	}

// 	fmt.Println("=== Example 2: Solana Payment Settlement ===")
// 	if err := exampleSettlement(x402Client); err != nil {
// 		log.Printf("Settlement example failed: %v", err)
// 	}
// }

// // addNetworkSupport configures Solana network
// func addNetworkSupport(client *x402.X402) error {
// 	solanaConfig := types.ClientConfig{
// 		Network:       types.NetworkSolanaDevnet,
// 		RPCUrl:        "https://api.devnet.solana.com",
// 		WSUrl:         "wss://api.devnet.solana.com",
// 		ChainID:       "solana-devnet",
// 		AcceptedDenom: "lamports",
// 	}
// 	if err := client.AddNetwork(types.NetworkSolanaDevnet, solanaConfig); err != nil {
// 		return fmt.Errorf("failed to add Solana devnet: %w", err)
// 	}
// 	return nil
// }

// func exampleVerification(client *x402.X402) error {
// 	payload := &types.VerifyRequest{
// 		X402Version:   1,
// 		PaymentHeader: "eyJ2ZXJzaW9uIjoxLCJjaGFpbklkIjoic29sYW5hLWRldm5ldCIsInBheW1lbnQiOnsiYW1vdW50IjoiMTAwIiwibWludCI6IlNPTCIsInBheWVyIjoiRUF4M29GNmttcEFhNmFSOUc2TGpodVdvcUtKTHBZc3VmU0RvR3AyZERXa2giLCJyZWNpcGllbnQiOiJBZWpIdVpkTnBEVWlBaXd1VjJOS1h6OEs2ZUx6Q2hZR3BUY3hwdGluV2JhciIsInR4QmFzZTY0IjoiQWJtdTYySENjL3FmV2tXUUxocGJzeFp1V2IyeHZaOHZlNjVCRlhzM1BVS1E3UVhSYk1PcGNMS1lTQzM0QkJBVGtDd2NheXVUbjR1WCthWjYxdnA0VVE0QkFBRUR3N1JtaXMyYS9SNGxLQnBvSi83ZmNzMnFSQWI5eFk1MTdxazVxYjIrS2ZxUFkzM05DUVNsckZEL2Z5S21QRmtTbDlhWUlmdTgvU25PL0NaS1QwQWdxd0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQVFPamNoVEVDSkloNWV1djV4VzcranMzOU43MEFCeE9OQlFCenBJeHVsajRCQWdJQUFRd0NBQUFBWkFBQUFBQUFBQUE9IiwicmVjZW50QmxvY2toYXNoIjoiNU5QMzdmdlVDS2l0aXVpMmM0ZE55ZkxoQWtwMjZIeGRIaWlVUzJ6c0NKSDMiLCJwdWJsaWNLZXkiOiJFQXgzb0Y2a21wQWE2YVI5RzZMamh1V29xS0pMcFlzdWZTRG9HcDJkRFdraCIsImZlZVBheWVyIjoiRUF4M29GNmttcEFhNmFSOUc2TGpodVdvcUtKTHBZc3VmU0RvR3AyZERXa2giLCJtZW1vIjoiIn0sInNpZ25hdHVyZSI6InVhN3JZY0p6K3A5YVJaQXVHbHV6Rm01WnZiRzlueTk3cmtFVmV6YzlRcER0QmRGc3c2bHdzcGhJTGZnRUVCT1FMQnhySzVPZmk1ZjVwbnJXK25oUkRnPT0ifQ==",
// 		PaymentRequirements: types.PaymentRequirements{
// 			Scheme:            "exact",
// 			Network:           "solana-devnet",
// 			MaxAmountRequired: "100000",
// 			Resource:          "https://localhost:8080/api/resource",
// 			Description:       "Access to Solana-based premium API resource",
// 			MimeType:          "application/json",
// 			PayTo:             "AejHuZdNpDUiAiwuV2NKXz8K6eLzChYGpTcxptinWbar",
// 			MaxTimeoutSeconds: 60,
// 			Asset:             "lamports",
// 		},
// 	}

// 	result, err := client.Verify(context.Background(), payload)
// 	if err != nil {
// 		return fmt.Errorf("verification failed: %w", err)
// 	}

// 	fmt.Println(result, err)

// 	fmt.Printf("Verification Result: Valid=%v, Error=%s\n", result.IsValid, result.InvalidReason)
// 	return nil
// }

// func exampleSettlement(client *x402.X402) error {
// 	payload := &types.VerifyRequest{
// 		X402Version:   1,
// 		PaymentHeader: "eyJ2ZXJzaW9uIjoxLCJjaGFpbklkIjoic29sYW5hLWRldm5ldCIsInBheW1lbnQiOnsiYW1vdW50IjoiMTAwIiwibWludCI6IlNPTCIsInBheWVyIjoiRUF4M29GNmttcEFhNmFSOUc2TGpodVdvcUtKTHBZc3VmU0RvR3AyZERXa2giLCJyZWNpcGllbnQiOiJBZWpIdVpkTnBEVWlBaXd1VjJOS1h6OEs2ZUx6Q2hZR3BUY3hwdGluV2JhciIsInR4QmFzZTY0IjoiQWJtdTYySENjL3FmV2tXUUxocGJzeFp1V2IyeHZaOHZlNjVCRlhzM1BVS1E3UVhSYk1PcGNMS1lTQzM0QkJBVGtDd2NheXVUbjR1WCthWjYxdnA0VVE0QkFBRUR3N1JtaXMyYS9SNGxLQnBvSi83ZmNzMnFSQWI5eFk1MTdxazVxYjIrS2ZxUFkzM05DUVNsckZEL2Z5S21QRmtTbDlhWUlmdTgvU25PL0NaS1QwQWdxd0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQVFPamNoVEVDSkloNWV1djV4VzcranMzOU43MEFCeE9OQlFCenBJeHVsajRCQWdJQUFRd0NBQUFBWkFBQUFBQUFBQUE9IiwicmVjZW50QmxvY2toYXNoIjoiNU5QMzdmdlVDS2l0aXVpMmM0ZE55ZkxoQWtwMjZIeGRIaWlVUzJ6c0NKSDMiLCJwdWJsaWNLZXkiOiJFQXgzb0Y2a21wQWE2YVI5RzZMamh1V29xS0pMcFlzdWZTRG9HcDJkRFdraCIsImZlZVBheWVyIjoiRUF4M29GNmttcEFhNmFSOUc2TGpodVdvcUtKTHBZc3VmU0RvR3AyZERXa2giLCJtZW1vIjoiIn0sInNpZ25hdHVyZSI6InVhN3JZY0p6K3A5YVJaQXVHbHV6Rm01WnZiRzlueTk3cmtFVmV6YzlRcER0QmRGc3c2bHdzcGhJTGZnRUVCT1FMQnhySzVPZmk1ZjVwbnJXK25oUkRnPT0ifQ==",
// 		PaymentRequirements: types.PaymentRequirements{
// 			Scheme:            "exact",
// 			Network:           "solana-devnet",
// 			MaxAmountRequired: "100000",
// 			Resource:          "https://localhost:8080/api/resource",
// 			Description:       "Access to Solana-based premium API resource",
// 			MimeType:          "application/json",
// 			PayTo:             "BG9ccUblGjvCLnKtjNsq73s7W8lPhwBe1vrxEaVB5PDvnyU",
// 			MaxTimeoutSeconds: 60,
// 			Asset:             "lamports",
// 		},
// 	}

// 	result, err := client.Settle(context.Background(), payload)
// 	if err != nil {
// 		return fmt.Errorf("settlement failed: %w", err)
// 	}

// 	fmt.Printf("Settlement Result: Success=%v, Error=%s\n", result.Success, result.Error)
// 	fmt.Println(result)
// 	return nil
// }
