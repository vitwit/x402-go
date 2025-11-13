package main

// import (
// 	"context"
// 	"fmt"
// 	"log"

// 	x402 "github.com/vitwit/x402"
// 	"github.com/vitwit/x402/types"
// )

// func main() {
// 	// Initialize the x402 library
// 	x402Client := x402.NewWithDefaults()
// 	defer x402Client.Close()

// 	// Add network support
// 	if err := addNetworkSupport(x402Client); err != nil {
// 		log.Fatal("Failed to configure networks:", err)
// 	}

// 	x, _ := x402Client.Supported()
// 	fmt.Println(x)

// 	// Example 1: Basic payment verification
// 	fmt.Println("=== Example 1: Payment Verification ===")
// 	if err := exampleVerification(x402Client); err != nil {
// 		log.Printf("Verification example failed: %v", err)
// 	}

// 	fmt.Println("=== Example 1: Payment Settlement ===")
// 	if err := exampleSettlement(x402Client); err != nil {
// 		log.Printf("Verification example failed: %v", err)
// 	}
// }

// // addNetworkSupport configures network clients
// func addNetworkSupport(client *x402.X402) error {

// 	// Add Cosmos Devnet support
// 	solanaConfig := types.ClientConfig{
// 		Network:       types.NetworkCosmosLocal,
// 		RPCUrl:        "http://locahost:26657",
// 		GRPCUrl:       "127.0.0.1:9090",
// 		WSUrl:         "ws://localhost:26657",
// 		ChainID:       "testnet",
// 		AcceptedDenom: "uregen",
// 	}
// 	if err := client.AddNetwork(types.NetworkCosmosLocal, solanaConfig); err != nil {
// 		return fmt.Errorf("failed to add Local network: %w", err)
// 	}

// 	return nil
// }

// // exampleVerification demonstrates payment verification
// func exampleVerification(client *x402.X402) error {
// 	// ctx := context.Background()

// 	// Create sample payment payload for EVM (Polygon)
// 	payload := &types.VerifyRequest{
// 		X402Version:   1,
// 		PaymentHeader: "ewogICJ2ZXJzaW9uIjogMSwKICAiY2hhaW5JZCI6ICJjb3Ntb3NodWItNCIsCiAgInBheW1lbnQiOiB7CiAgICAiYW1vdW50IjogIjEwMDAiLAogICAgImRlbm9tIjogInVyZWdlbiIsCiAgICAicGF5ZXIiOiAicmVnZW4xOXR3djJtY243d3N1cjRzanJ1Y250aHU4ejJtdzh1a3drN2Z3aHMiLAogICAgInJlY2lwaWVudCI6ICJyZWdlbjE5dHU5bHRoeGQyOWN3em5jMmQ3NjQycDcydjBrbmp3enlxZWxkZSIsCiAgICAidHhCYXNlNjQiOiAiQ284QkNvd0JDaHd2WTI5emJXOXpMbUpoYm1zdWRqRmlaWFJoTVM1TmMyZFRaVzVrRW13S0xISmxaMlZ1TVRsMGQzWXliV051TjNkemRYSTBjMnB5ZFdOdWRHaDFPSG95YlhjNGRXdDNhemRtZDJoekVpeHlaV2RsYmpFNWRIVTViSFJvZUdReU9XTjNlbTVqTW1RM05qUXljRGN5ZGpCcmJtcDNlbmx4Wld4a1pSb09DZ1oxY21WblpXNFNCREV3TURBU2FBcFFDa1lLSHk5amIzTnRiM011WTNKNWNIUnZMbk5sWTNBeU5UWnJNUzVRZFdKTFpYa1NJd29oQXhZYWpqTEQ5ekJrVDBkazJhZUwvaHdKc0UwRmxXRnVEK1k3SjRCNkoyTFlFZ1FLQWdnQkdBMFNGQW9PQ2daMWNtVm5aVzRTQkRVd01EQVF3Sm9NR2tCZTB1RzRBWUVwU2ZSc2JnZWJEdUNJejNWOTZHL0wzMzZjU3hCdWRHeWt0WGhITlpKbVdlcjUyN2p3SVh1V3dGRjF0bThKdlVTYWFQMGFEdjR4Y3dTKyIsCiAgICAicHVibGljS2V5IjogIkExQjJDMy4uLiIsCiAgICAiZmVlIjogIjUwMDAiLAogICAgImdhcyI6ICIyMDAwMDAiLAogICAgIm1lbW8iOiAieDQwMiBwYXltZW50IiwKICAgICJzZXF1ZW5jZSI6ICI0MiIsCiAgICAiYWNjb3VudE51bWJlciI6ICIxMDEiCiAgfSwKICAic2lnbmF0dXJlIjogIlh0TGh1QUdCS1VuMGJHNEhtdzdnaU05MWZlaHZ5OTkrbkVzUWJuUnNwTFY0UnpXU1psbnErZHU0OENGN2xzQlJkYlp2Q2IxRW1tajlHZzcrTVhNRXZnPT0iCn0K",
// 		PaymentRequirements: types.PaymentRequirements{
// 			Scheme:            "exact",
// 			Network:           "testnet",
// 			MaxAmountRequired: "100", // 1 REGEN = 1_000_000 uregen
// 			Resource:          "http://localhost:8080/api/resource",
// 			Description:       "Access to premium API resource",
// 			MimeType:          "application/json",
// 			OutputSchema:      nil,
// 			PayTo:             "regen19tu9lthxd29cwznc2d7642p72v0knjwzyqelde",
// 			MaxTimeoutSeconds: 60,
// 			Asset:             "uregen",
// 			Extra: map[string]interface{}{
// 				"name":    "Regen Token",
// 				"version": "v1",
// 			},
// 		},
// 	}

// 	// Perform quick verification (no blockchain queries)
// 	quickResult, err := client.Verify(context.Background(), payload)
// 	if err != nil {
// 		return fmt.Errorf("quick verification failed: %w", err)
// 	}

// 	fmt.Printf("Quick Verification Result: Valid=%v, Error=%s\n",
// 		quickResult.IsValid, quickResult.InvalidReason)

// 	// Perform full verification (with blockchain queries)
// 	// Note: This would fail in the example since we don't have a real transaction
// 	// fullResult, err := client.VerifyWithObjects(ctx, payload, requirements)
// 	// if err != nil {
// 	// 	return fmt.Errorf("full verification failed: %w", err)
// 	// }

// 	// fmt.Printf("Full Verification Result: Valid=%v, Error=%s\n",
// 	// 	fullResult.Valid, fullResult.Error)

// 	return nil
// }

// // exampleVerification demonstrates payment verification
// func exampleSettlement(client *x402.X402) error {
// 	// ctx := context.Background()

// 	// Create sample payment payload for EVM (Polygon)
// 	payload := &types.VerifyRequest{
// 		X402Version:   1,
// 		PaymentHeader: "ewogICJ2ZXJzaW9uIjogMSwKICAiY2hhaW5JZCI6ICJjb3Ntb3NodWItNCIsCiAgInBheW1lbnQiOiB7CiAgICAiYW1vdW50IjogIjEwMDAiLAogICAgImRlbm9tIjogInVyZWdlbiIsCiAgICAicGF5ZXIiOiAicmVnZW4xOXR3djJtY243d3N1cjRzanJ1Y250aHU4ejJtdzh1a3drN2Z3aHMiLAogICAgInJlY2lwaWVudCI6ICJyZWdlbjE5dHU5bHRoeGQyOWN3em5jMmQ3NjQycDcydjBrbmp3enlxZWxkZSIsCiAgICAidHhCYXNlNjQiOiAiQ284QkNvd0JDaHd2WTI5emJXOXpMbUpoYm1zdWRqRmlaWFJoTVM1TmMyZFRaVzVrRW13S0xISmxaMlZ1TVRsMGQzWXliV051TjNkemRYSTBjMnB5ZFdOdWRHaDFPSG95YlhjNGRXdDNhemRtZDJoekVpeHlaV2RsYmpFNWRIVTViSFJvZUdReU9XTjNlbTVqTW1RM05qUXljRGN5ZGpCcmJtcDNlbmx4Wld4a1pSb09DZ1oxY21WblpXNFNCREV3TURBU2FBcFFDa1lLSHk5amIzTnRiM011WTNKNWNIUnZMbk5sWTNBeU5UWnJNUzVRZFdKTFpYa1NJd29oQXhZYWpqTEQ5ekJrVDBkazJhZUwvaHdKc0UwRmxXRnVEK1k3SjRCNkoyTFlFZ1FLQWdnQkdBMFNGQW9PQ2daMWNtVm5aVzRTQkRVd01EQVF3Sm9NR2tCZTB1RzRBWUVwU2ZSc2JnZWJEdUNJejNWOTZHL0wzMzZjU3hCdWRHeWt0WGhITlpKbVdlcjUyN2p3SVh1V3dGRjF0bThKdlVTYWFQMGFEdjR4Y3dTKyIsCiAgICAicHVibGljS2V5IjogIkExQjJDMy4uLiIsCiAgICAiZmVlIjogIjUwMDAiLAogICAgImdhcyI6ICIyMDAwMDAiLAogICAgIm1lbW8iOiAieDQwMiBwYXltZW50IiwKICAgICJzZXF1ZW5jZSI6ICI0MiIsCiAgICAiYWNjb3VudE51bWJlciI6ICIxMDEiCiAgfSwKICAic2lnbmF0dXJlIjogIlh0TGh1QUdCS1VuMGJHNEhtdzdnaU05MWZlaHZ5OTkrbkVzUWJuUnNwTFY0UnpXU1psbnErZHU0OENGN2xzQlJkYlp2Q2IxRW1tajlHZzcrTVhNRXZnPT0iCn0K",
// 		PaymentRequirements: types.PaymentRequirements{
// 			Scheme:            "exact",
// 			Network:           "testnet",
// 			MaxAmountRequired: "100", // 1 REGEN = 1_000_000 uregen
// 			Resource:          "http://localhost:8080/api/resource",
// 			Description:       "Access to premium API resource",
// 			MimeType:          "application/json",
// 			OutputSchema:      nil,
// 			PayTo:             "regen19tu9lthxd29cwznc2d7642p72v0knjwzyqelde",
// 			MaxTimeoutSeconds: 60,
// 			Asset:             "uregen",
// 			Extra: map[string]interface{}{
// 				"name":    "Regen Token",
// 				"version": "v1",
// 			},
// 		},
// 	}

// 	// Perform quick verification (no blockchain queries)
// 	quickResult, err := client.Settle(context.Background(), payload)
// 	if err != nil {
// 		return fmt.Errorf("quick verification failed: %w", err)
// 	}

// 	fmt.Printf("Quick Verification Result: Valid=%v, Error=%s\n",
// 		quickResult.Success, quickResult.Error)
// 	fmt.Println(quickResult)

// 	// Perform full verification (with blockchain queries)
// 	// Note: This would fail in the example since we don't have a real transaction
// 	// fullResult, err := client.VerifyWithObjects(ctx, payload, requirements)
// 	// if err != nil {
// 	// 	return fmt.Errorf("full verification failed: %w", err)
// 	// }

// 	// fmt.Printf("Full Verification Result: Valid=%v, Error=%s\n",
// 	// 	fullResult.Valid, fullResult.Error)

// 	return nil
// }
