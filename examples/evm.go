package examples

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	x402 "github.com/vitwit/x402"
	"github.com/vitwit/x402/types"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/vitwit/x402/utils/eip712"
)

func EVM() {
	client := x402.New(&types.X402Config{
		DefaultTimeout: time.Minute,
		RetryCount:     3,
		LogLevel:       "",
		EnableMetrics:  false,
	})
	defer client.Close()

	if err := addEvmNetworkSupport(client); err != nil {
		log.Fatal(err)
	}

	if err := exampleEvmVerification(client); err != nil {
		log.Fatal("EVM verification failed:", err)
	}
}

func addEvmNetworkSupport(client *x402.X402) error {
	return client.AddNetwork("base-sepolia", types.ChainEVM, types.ClientConfig{
		Network:       "base-sepolia",
		RPCUrl:        "https://sepolia.base.org",
		ChainID:       "84532",
		AcceptedDenom: "USDC",
		X402Version:   1,
		ChainFamily:   types.ChainEVM,
	})
}

func exampleEvmVerification(client *x402.X402) error {
	//------------------------------------------------------------
	// 1. Generate random wallet
	//------------------------------------------------------------
	priv, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(priv.PublicKey).Hex()

	//------------------------------------------------------------
	// 2. Build EIP-3009 authorization message
	//------------------------------------------------------------

	auth := types.EVMAuthorization{
		From:        from,
		To:          "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
		Value:       "10000",
		ValidAfter:  int(time.Now().Unix() - 5),
		ValidBefore: int(time.Now().Unix() + 60),
		Nonce:       "0xabc123",
	}

	//------------------------------------------------------------
	// 3. Compute EIP-712 digest
	//------------------------------------------------------------

	digest, err := eip712.BuildTransferWithAuthDigest(
		eip712.EIP712Domain{
			Name:              "USDC",
			Version:           "2",
			ChainId:           "84532",
			VerifyingContract: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
		},
		auth.From,
		auth.To,
		auth.Value,
		strconv.Itoa(auth.ValidAfter),
		strconv.Itoa(auth.ValidBefore),
		auth.Nonce,
	)
	if err != nil {
		return fmt.Errorf("digest failed: %w", err)
	}

	//------------------------------------------------------------
	// 4. Sign digest
	//------------------------------------------------------------

	sigBytes, err := crypto.Sign(digest.Bytes(), priv)
	if err != nil {
		return fmt.Errorf("sign failed: %w", err)
	}

	// Fix V from 0/1 → 27/28
	if sigBytes[64] < 27 {
		sigBytes[64] += 27
	}
	signature := fmt.Sprintf("0x%x", sigBytes)

	//------------------------------------------------------------
	// 5. Build PaymentPayload (x402 spec)
	//------------------------------------------------------------

	p1 := types.EthereumPermitPayload{
		Signature:     signature,
		Authorization: auth,
	}
	bz, _ := json.Marshal(p1)

	paymentPayload := types.PaymentPayload{
		X402Version: 1,
		Scheme:      "exact",
		Network:     "base-sepolia",
		Payload:     string(bz),
	}

	//------------------------------------------------------------
	// 6. Build PaymentRequirements (x402 spec)
	//------------------------------------------------------------

	req := &types.VerifyRequest{
		X402Version:    1,
		PaymentPayload: paymentPayload,
		PaymentRequirements: types.PaymentRequirements{
			Scheme:            "exact",
			Network:           "base-sepolia",
			MaxAmountRequired: "10000",
			Resource:          "https://api.example.com/data",
			Description:       "Premium data",
			MimeType:          "application/json",
			PayTo:             auth.To, // must match authorization.to
			MaxTimeoutSeconds: 60,
			Asset:             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
			Extra: map[string]interface{}{
				"name":    "USDC",
				"version": "2",
			},
		},
	}

	//------------------------------------------------------------
	// 7. Run Verify()
	//----------------
	// --------------------------------------------

	result, err := client.Verify(context.Background(), req)
	if err != nil {
		return fmt.Errorf("verify error: %w", err)
	}

	fmt.Println("Verification Result:", result)
	return nil
}
