package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
	"strconv"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/vitwit/x402/clients"
	"github.com/vitwit/x402/utils/eip712"
)

func init() {
	// Add Anvil to the SDK's internal map for this test
	clients.EVMNetworkToChainId["eip155:31337"] = 31337
}

const (
	serverURL = "http://localhost:8080"
	payerPriv = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" // Anvil Account 1
	usdcAddr  = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eb48"
	recipient = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" // Anvil Account 0
)

func main() {
	log.Println("--- Starting x402 V2 Automated E2E Test ---")

	// 1. Health Check
	if !checkHealth() {
		log.Fatal("Server is not healthy")
	}
	log.Println("Server is healthy")

	// 2. Discovery
	testDiscovery()

	// 3. SIWx Session
	sessionID := testSIWxSession()
	if sessionID == "" {
		log.Fatal("Failed to create session")
	}
	log.Println("Session Created:", sessionID)

	// 4. Payment Verification (V2)
	testPaymentVerification(sessionID)

	// 5. Payment Settlement (V2)
	testPaymentSettlement(sessionID)

	log.Println("--- E2E Test Completed Successfully ---")
}

func checkHealth() bool {
	resp, err := http.Get(serverURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func testDiscovery() {
	log.Println("Testing Discovery...")
	resp, err := http.Get(serverURL + "/x402/discovery")
	if err != nil {
		log.Printf("Discovery failed: %v", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var disc map[string]interface{}
	json.Unmarshal(body, &disc)
	log.Printf("Service Name: %v, Version: %v", disc["name"], disc["x402Version"])
}

func testSIWxSession() string {
	log.Println("Testing SIWx Session Creation...")
	payload := map[string]interface{}{
		"message": map[string]interface{}{
			"domain":   "localhost",
			"address":  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			"uri":      "http://localhost:8080",
			"version":  "1",
			"chainId":  "eip155:31337",
			"nonce":    "12345678",
			"issuedAt": time.Now().Format(time.RFC3339),
		},
		"signature": "MOCK_SIGNATURE",
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(serverURL+"/x402/sessions", "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("Session creation failed: %v", err)
		return ""
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		log.Printf("Session creation failed: %d %s", resp.StatusCode, string(b))
		return ""
	}

	var session map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&session)
	return session["id"].(string)
}

func testPaymentVerification(sessionID string) {
	log.Println("Testing Payment Verification...")
	
	// 1. Generate real EIP-3009 payload for Anvil
	priv, _ := crypto.HexToECDSA(payerPriv)
	from := crypto.PubkeyToAddress(priv.PublicKey).Hex()
	
	validAfter := time.Now().Unix() - 10
	validBefore := time.Now().Unix() + 300
	nonce := "0x" + fmt.Sprintf("%x", crypto.Keccak256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10))))
	amount := "1000000" // 1 USDC if 6 decimals

	domain := eip712.EIP712Domain{
		Name:              "USDC",
		Version:           "2",
		ChainId:           "31337",
		VerifyingContract: usdcAddr,
	}

	digest, err := eip712.BuildTransferWithAuthDigest(
		domain,
		from,
		recipient,
		amount,
		strconv.FormatInt(validAfter, 10),
		strconv.FormatInt(validBefore, 10),
		nonce,
	)
	if err != nil {
		log.Fatalf("Digest failed: %v", err)
	}

	sigBytes, _ := crypto.Sign(digest.Bytes(), priv)
	if sigBytes[64] < 27 {
		sigBytes[64] += 27
	}
	signature := "0x" + fmt.Sprintf("%x", sigBytes)

	paymentPayload := map[string]interface{}{
		"x402Version": 2,
		"payload": map[string]interface{}{
			"signature": signature,
			"authorization": map[string]interface{}{
				"from":        from,
				"to":          recipient,
				"value":       amount,
				"validAfter":  strconv.FormatInt(validAfter, 10),
				"validBefore": strconv.FormatInt(validBefore, 10),
				"nonce":       nonce,
			},
		},
		"accepted": map[string]interface{}{
			"scheme":            "exact",
			"network":           "eip155:31337",
			"asset":             usdcAddr,
			"amount":            amount,
			"payTo":             recipient,
			"maxTimeoutSeconds": 300,
			"extra": map[string]interface{}{
				"name":    "USDC",
				"version": "2",
			},
		},
	}

	body, _ := json.Marshal(paymentPayload)
	hReq, _ := http.NewRequest("POST", serverURL+"/api/v1/verify", bytes.NewBuffer(body))
	hReq.Header.Set("Content-Type", "application/json")
	hReq.Header.Set("X-SESSION-ID", sessionID)
	hReq.Header.Set("PAYMENT-SIGNATURE", string(body))

	client := &http.Client{}
	resp, err := client.Do(hReq)
	if err != nil {
		log.Printf("Verification failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	log.Printf("Verification result: %d %s", resp.StatusCode, string(body))
}

func testPaymentSettlement(sessionID string) {
	log.Println("Testing Payment Settlement...")

	// 1. Generate real EIP-3009 payload (same as verification for simplicity in this mock)
	priv, _ := crypto.HexToECDSA(payerPriv)
	from := crypto.PubkeyToAddress(priv.PublicKey).Hex()

	validAfter := time.Now().Unix() - 10
	validBefore := time.Now().Unix() + 300
	nonce := "0x" + fmt.Sprintf("%x", crypto.Keccak256([]byte(strconv.FormatInt(time.Now().UnixNano()+1, 10))))
	amount := "1000000"

	domain := eip712.EIP712Domain{
		Name:              "USDC",
		Version:           "2",
		ChainId:           "31337",
		VerifyingContract: usdcAddr,
	}

	digest, _ := eip712.BuildTransferWithAuthDigest(
		domain,
		from,
		recipient,
		amount,
		strconv.FormatInt(validAfter, 10),
		strconv.FormatInt(validBefore, 10),
		nonce,
	)

	sigBytes, _ := crypto.Sign(digest.Bytes(), priv)
	if sigBytes[64] < 27 {
		sigBytes[64] += 27
	}
	signature := "0x" + fmt.Sprintf("%x", sigBytes)

	paymentPayload := map[string]interface{}{
		"x402Version": 2,
		"payload": map[string]interface{}{
			"signature": signature,
			"authorization": map[string]interface{}{
				"from":        from,
				"to":          recipient,
				"value":       amount,
				"validAfter":  strconv.FormatInt(validAfter, 10),
				"validBefore": strconv.FormatInt(validBefore, 10),
				"nonce":       nonce,
			},
		},
		"accepted": map[string]interface{}{
			"scheme":            "exact",
			"network":           "eip155:31337",
			"asset":             usdcAddr,
			"amount":            amount,
			"payTo":             recipient,
			"maxTimeoutSeconds": 300,
			"extra": map[string]interface{}{
				"name":    "USDC",
				"version": "2",
			},
		},
	}

	body, _ := json.Marshal(paymentPayload)
	hReq, _ := http.NewRequest("POST", serverURL+"/api/v1/settle", bytes.NewBuffer(body))
	hReq.Header.Set("Content-Type", "application/json")
	hReq.Header.Set("X-SESSION-ID", sessionID)
	hReq.Header.Set("PAYMENT-SIGNATURE", string(body))

	client := &http.Client{}
	resp, err := client.Do(hReq)
	if err != nil {
		log.Printf("Settlement failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	log.Printf("Settlement result: %d %s", resp.StatusCode, string(body))
}
