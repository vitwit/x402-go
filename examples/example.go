package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"time"

	x402 "github.com/vitwit/x402"
	x402types "github.com/vitwit/x402/types"

	"github.com/vitwit/x402/clients"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	RPC_URL       = "http://127.0.0.1:8545"
	CHAIN_ID      = "1337"
	MOCK_USDC     = "tc"
	RECIPIENT     = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
	ANVIL_PRIVKEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)

func main() {
	fmt.Println("=== EIP-3009 x402 Example ===")

	// Create x402 unified client
	x402Client := x402.NewWithDefaults()
	defer x402Client.Close()

	// Add EVM network config
	if err := addNetworkSupport(x402Client); err != nil {
		log.Fatal("Network config failed:", err)
	}

	// Run the example
	if err := exampleEIP3009(x402Client); err != nil {
		log.Println("Error:", err)
	}
}

func addNetworkSupport(client *x402.X402) error {
	cfg := x402types.ClientConfig{
		Network:       x402types.NetworkBaseAnvil,
		RPCUrl:        RPC_URL,
		ChainID:       CHAIN_ID,
		AcceptedDenom: "USDC",
		PrivHex:       ANVIL_PRIVKEY,
	}
	return client.AddNetwork(x402types.NetworkBaseAnvil, cfg)
}

func exampleEIP3009(client *x402.X402) error {
	ctx := context.Background()

	// ---------------------------
	// Build EIP-3009 authorization
	// ---------------------------
	priv, _ := crypto.HexToECDSA(ANVIL_PRIVKEY)
	authorizer := crypto.PubkeyToAddress(priv.PublicKey)
	recipient := common.HexToAddress(RECIPIENT)
	usdc := common.HexToAddress(MOCK_USDC)

	value := big.NewInt(1_000_000) // 1 USDC
	validAfter := big.NewInt(0)
	validBefore := big.NewInt(time.Now().Add(15 * time.Minute).Unix())

	// nonce
	nonceHash := sha256.Sum256([]byte(fmt.Sprintf("nonce-%d", time.Now().UnixNano())))
	var nonceArr [32]byte
	copy(nonceArr[:], nonceHash[:])
	nonceHex := "0x" + hex.EncodeToString(nonceHash[:])

	// Build temporary EthereumClient (only for digest)
	ethTemp, _ := clients.NewEVMClient(
		RPC_URL,
		big.NewInt(1337),
		MOCK_USDC,
		x402types.NetworkBaseAnvil,
		ANVIL_PRIVKEY,
	)

	// digest creation
	digest := ethTemp.GetEIP3009Digest(
		usdc, authorizer, recipient,
		value, validAfter, validBefore, nonceArr,
	)

	// sign
	sig, err := crypto.Sign(digest, priv)
	if err != nil || len(sig) != 65 {
		log.Fatalf("signature failed: %v", err)
	}
	r := sig[:32]
	s := sig[32:64]
	v := sig[64] + 27

	// ---------------------------
	// Build x402 payload
	// ---------------------------
	header := clients.EthereumPaymentPayload{
		Version: 1,
		ChainID: CHAIN_ID,
		Payment: clients.EthereumPaymentData{
			Amount:      value.String(),
			Token:       usdc.Hex(),
			Payer:       authorizer.Hex(),
			Recipient:   recipient.Hex(),
			PaymentType: "eip3009",
			EIP3009Data: &clients.EIP3009TransferData{
				From:        authorizer.Hex(),
				To:          recipient.Hex(),
				Value:       value.String(),
				ValidAfter:  validAfter.String(),
				ValidBefore: validBefore.String(),
				Nonce:       nonceHex,
				V:           uint8(v),
				R:           "0x" + hex.EncodeToString(r),
				S:           "0x" + hex.EncodeToString(s),
			},
		},
	}

	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.StdEncoding.EncodeToString(headerBytes)

	req := &x402types.VerifyRequest{
		X402Version:   1,
		PaymentHeader: headerB64,
		PaymentRequirements: x402types.PaymentRequirements{
			Scheme:            "exact",
			Network:           string(x402types.NetworkBaseAnvil),
			MaxAmountRequired: value.String(),
			PayTo:             recipient.Hex(),
			Description:       "EIP3009 transfer",
			Asset:             "USDC",
			MaxTimeoutSeconds: 600,
		},
	}

	// ---------------------------
	// VERIFY
	// ---------------------------
	fmt.Println("\nRunning Verify() ...")
	verifyRes, err := client.Verify(ctx, req)
	if err != nil {
		log.Fatalf("Verify error: %v", err)
	}
	fmt.Printf("Verify Result: %+v\n", verifyRes)

	// ---------------------------
	// SETTLE (broadcast)
	// ---------------------------
	fmt.Println("\nRunning Settle() ...")
	settleRes, err := client.Settle(ctx, req)
	if err != nil {
		log.Fatalf("Settle error: %v", err)
	}
	fmt.Printf("Settle Result: %+v\n", settleRes)

	return nil
}
