package main

// import (
// 	"context"
// 	"encoding/base64"
// 	"encoding/hex"
// 	"encoding/json"
// 	"fmt"
// 	"log"
// 	"math/big"

// 	x402 "github.com/vitwit/x402"
// 	x402types "github.com/vitwit/x402/types"

// 	"github.com/ethereum/go-ethereum/common"
// 	"github.com/ethereum/go-ethereum/core/types"
// 	"github.com/ethereum/go-ethereum/crypto"
// 	"github.com/ethereum/go-ethereum/ethclient"
// )

// func main() {
// 	fmt.Println("=== Ethereum x402 Example ===")

// 	x402Client := x402.NewWithDefaults()
// 	defer x402Client.Close()

// 	if err := addNetworkSupport(x402Client); err != nil {
// 		log.Fatal("Failed to configure networks:", err)
// 	}

// 	supported, _ := x402Client.Supported()
// 	fmt.Println("Supported Networks:", supported)

// 	fmt.Println("\n=== Example 1: Verify Ethereum Payment ===")
// 	if err := exampleVerification(x402Client); err != nil {
// 		log.Printf("Verification failed: %v", err)
// 	}
// }

// func addNetworkSupport(client *x402.X402) error {
// 	cfg := x402types.ClientConfig{
// 		Network:       x402types.NetworkBaseAnvil,
// 		RPCUrl:        "http://127.0.0.1:8545",
// 		ChainID:       "1337",
// 		AcceptedDenom: "ETH",
// 	}
// 	return client.AddNetwork(x402types.NetworkBaseAnvil, cfg)
// }

// func exampleVerification(client *x402.X402) error {
// 	ctx := context.Background()

// 	privateKey, _ := crypto.HexToECDSA("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
// 	toAddr := common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")

// 	ethClient, err := ethclient.Dial("http://127.0.0.1:8545")
// 	if err != nil {
// 		log.Fatalf("dial eth rpc: %v", err)
// 	}
// 	defer ethClient.Close()

// 	fromAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
// 	nonce, err := ethClient.PendingNonceAt(ctx, fromAddr)
// 	if err != nil {
// 		log.Fatalf("get pending nonce: %v", err)
// 	}

// 	tx := types.NewTransaction(
// 		nonce,
// 		toAddr,
// 		big.NewInt(2e15), // 0.002 ETH
// 		21000,
// 		big.NewInt(1e9),
// 		nil,
// 	)

// 	signedTx, _ := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(1337)), privateKey)
// 	txBytes, _ := signedTx.MarshalBinary()
// 	txHex := "0x" + hex.EncodeToString(txBytes)

// 	header := x402types.EthereumPaymentPayload{
// 		Payment: struct {
// 			TxHex string `json:"txHex"`
// 		}{
// 			TxHex: txHex,
// 		},
// 	}

// 	headerJSON, _ := json.Marshal(header)
// 	headerB64 := base64.StdEncoding.EncodeToString(headerJSON)

// 	payload := &x402types.VerifyRequest{
// 		X402Version:   1,
// 		PaymentHeader: headerB64,
// 		PaymentRequirements: x402types.PaymentRequirements{
// 			Scheme:            "exact",
// 			Network:           string(x402types.NetworkBaseAnvil),
// 			MaxAmountRequired: "2000000000000000", // 0.002 ETH in wei
// 			PayTo:             toAddr.Hex(),
// 			Description:       "Local payment test",
// 			Asset:             "ETH",
// 			MaxTimeoutSeconds: 600,
// 		},
// 	}

// 	fmt.Println("Running VerifyPayment() ...")
// 	result, err := client.Verify(ctx, payload)
// 	if err != nil {
// 		log.Fatalf("verification failed: %v", err)
// 	}
// 	fmt.Printf("Verification Result: %+v\n", result)

// 	fmt.Println("Broadcasting via SettlePayment() ...")
// 	settle, err := client.Settle(ctx, payload)
// 	if err != nil {
// 		log.Fatalf("settlement failed: %v", err)
// 	}
// 	fmt.Printf("Settlement: %+v\n", settle)
// 	return nil
// }
