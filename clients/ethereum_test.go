package clients

// import (
// 	"context"
// 	"crypto/ecdsa"
// 	"encoding/base64"
// 	"encoding/hex"
// 	"encoding/json"
// 	"math/big"
// 	"testing"
// 	"time"

// 	"github.com/ethereum/go-ethereum/common"
// 	"github.com/ethereum/go-ethereum/core/types"
// 	"github.com/ethereum/go-ethereum/crypto"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"
// 	x402types "github.com/vitwit/x402/types"
// )

// const (
// 	anvilRPC     = "http://127.0.0.1:8545"
// 	anvilChainID = 1337
// )

// var (
// 	testPrivateKey   = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
// 	testAddress      = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
// 	recipientAddress = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
// )

// func TestEthereumClient_Connection(t *testing.T) {
// 	client, err := NewEthereumClient(anvilRPC, big.NewInt(anvilChainID), "ETH")
// 	require.NoError(t, err)
// 	require.NotNil(t, client)
// 	defer client.Close()

// 	ctx := context.Background()
// 	chainID, err := client.client.ChainID(ctx)
// 	require.NoError(t, err)
// 	assert.Equal(t, int64(anvilChainID), chainID.Int64())

// 	t.Logf("✅ Connected to Anvil - Chain ID: %d", chainID.Int64())
// }

// func TestEthereumClient_VerifyNativeETH(t *testing.T) {
// 	client, err := NewEthereumClient(anvilRPC, big.NewInt(anvilChainID), "ETH")
// 	require.NoError(t, err)
// 	defer client.Close()

// 	ctx := context.Background()

// 	// Load private key
// 	privateKey, err := crypto.HexToECDSA(testPrivateKey)
// 	require.NoError(t, err)

// 	fromAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
// 	toAddr := common.HexToAddress(recipientAddress)

// 	// Get nonce
// 	nonce, err := client.client.PendingNonceAt(ctx, fromAddr)
// 	require.NoError(t, err)

// 	// Create transaction - 0.002 ETH
// 	amount := big.NewInt(2e15)
// 	gasPrice := big.NewInt(1e9)

// 	tx := types.NewTransaction(
// 		nonce,
// 		toAddr,
// 		amount,
// 		21000,
// 		gasPrice,
// 		nil,
// 	)

// 	// Sign transaction
// 	signer := types.NewEIP155Signer(big.NewInt(anvilChainID))
// 	signedTx, err := types.SignTx(tx, signer, privateKey)
// 	require.NoError(t, err)

// 	// Encode transaction
// 	txBytes, err := signedTx.MarshalBinary()
// 	require.NoError(t, err)

// 	t.Logf("📝 Transaction created:")
// 	t.Logf("   From: %s", fromAddr.Hex())
// 	t.Logf("   To: %s", toAddr.Hex())
// 	t.Logf("   Amount: %s wei (0.002 ETH)", amount.String())
// 	t.Logf("   Hash: %s", signedTx.Hash().Hex())

// 	// Create payment header
// 	paymentData := EthereumPaymentData{
// 		Amount:      amount.String(),
// 		Token:       "ETH",
// 		Payer:       fromAddr.Hex(),
// 		Recipient:   toAddr.Hex(),
// 		PaymentType: "native",
// 		TxHash:      signedTx.Hash().Hex(),
// 		SignedTx:    hex.EncodeToString(txBytes),
// 		Nonce:       big.NewInt(int64(nonce)).String(),
// 		GasPrice:    gasPrice.String(),
// 		GasLimit:    "21000",
// 	}

// 	header := EthereumPaymentPayload{
// 		Version: 1,
// 		ChainID: big.NewInt(anvilChainID).String(),
// 		Payment: paymentData,
// 	}

// 	headerJSON, err := json.Marshal(header)
// 	require.NoError(t, err)

// 	// Create verify request
// 	verifyReq := &x402types.VerifyRequest{
// 		PaymentHeader: base64.StdEncoding.EncodeToString(headerJSON),
// 		PaymentRequirements: x402types.PaymentRequirements{
// 			PayTo:             toAddr.Hex(),
// 			MaxAmountRequired: "0.001", // Require at least 0.001 ETH
// 		},
// 	}

// 	t.Logf("🔍 Verifying payment...")

// 	// Verify payment
// 	result, err := client.VerifyPayment(ctx, verifyReq)
// 	require.NoError(t, err)

// 	t.Logf("✅ Verification Result:")
// 	t.Logf("   Valid: %v", result.IsValid)
// 	t.Logf("   Amount: %s ETH", result.Amount.String())
// 	t.Logf("   Token: %s", result.Token)
// 	t.Logf("   Sender: %s", result.Sender)
// 	t.Logf("   Recipient: %s", result.Recipient)

// 	assert.True(t, result.IsValid)
// 	assert.Equal(t, "0.002", result.Amount.String())
// 	assert.Equal(t, "ETH", result.Token)
// 	assert.Equal(t, toAddr.Hex(), result.Recipient)
// 	assert.Equal(t, fromAddr.Hex(), result.Sender)
// }

// func TestEthereumClient_BroadcastTransaction(t *testing.T) {
// 	client, err := NewEthereumClient(anvilRPC, big.NewInt(anvilChainID), "ETH")
// 	require.NoError(t, err)
// 	defer client.Close()

// 	ctx := context.Background()

// 	privateKey, err := crypto.HexToECDSA(testPrivateKey)
// 	require.NoError(t, err)

// 	fromAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
// 	toAddr := common.HexToAddress(recipientAddress)

// 	nonce, err := client.client.PendingNonceAt(ctx, fromAddr)
// 	require.NoError(t, err)

// 	amount := big.NewInt(2e15) // 0.002 ETH
// 	gasPrice := big.NewInt(1e9)

// 	tx := types.NewTransaction(
// 		nonce,
// 		toAddr,
// 		amount,
// 		21000,
// 		gasPrice,
// 		nil,
// 	)

// 	signer := types.NewEIP155Signer(big.NewInt(anvilChainID))
// 	signedTx, err := types.SignTx(tx, signer, privateKey)
// 	require.NoError(t, err)

// 	t.Logf("📡 Broadcasting transaction: %s", signedTx.Hash().Hex())

// 	// Broadcast transaction
// 	err = client.client.SendTransaction(ctx, signedTx)
// 	require.NoError(t, err)

// 	t.Logf("⏳ Waiting for transaction receipt...")

// 	// Wait for receipt
// 	receipt, err := waitForReceipt(ctx, client, signedTx.Hash(), 30*time.Second)
// 	require.NoError(t, err)

// 	t.Logf("✅ Transaction mined:")
// 	t.Logf("   Block: %d", receipt.BlockNumber.Uint64())
// 	t.Logf("   Status: %d", receipt.Status)
// 	t.Logf("   Gas Used: %d", receipt.GasUsed)

// 	assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
// }

// func TestEthereumClient_InsufficientAmount(t *testing.T) {
// 	client, err := NewEthereumClient(anvilRPC, big.NewInt(anvilChainID), "ETH")
// 	require.NoError(t, err)
// 	defer client.Close()

// 	ctx := context.Background()

// 	privateKey, err := crypto.HexToECDSA(testPrivateKey)
// 	require.NoError(t, err)

// 	fromAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
// 	toAddr := common.HexToAddress(recipientAddress)

// 	nonce, err := client.client.PendingNonceAt(ctx, fromAddr)
// 	require.NoError(t, err)

// 	// Send only 0.0001 ETH (insufficient)
// 	amount := big.NewInt(1e14)
// 	gasPrice := big.NewInt(1e9)

// 	tx := types.NewTransaction(nonce, toAddr, amount, 21000, gasPrice, nil)
// 	signer := types.NewEIP155Signer(big.NewInt(anvilChainID))
// 	signedTx, err := types.SignTx(tx, signer, privateKey)
// 	require.NoError(t, err)

// 	txBytes, err := signedTx.MarshalBinary()
// 	require.NoError(t, err)

// 	paymentData := EthereumPaymentData{
// 		Amount:      amount.String(),
// 		Token:       "ETH",
// 		Payer:       fromAddr.Hex(),
// 		Recipient:   toAddr.Hex(),
// 		PaymentType: "native",
// 		TxHash:      signedTx.Hash().Hex(),
// 		SignedTx:    hex.EncodeToString(txBytes),
// 	}

// 	header := EthereumPaymentPayload{
// 		Version: 1,
// 		ChainID: big.NewInt(anvilChainID).String(),
// 		Payment: paymentData,
// 	}

// 	headerJSON, err := json.Marshal(header)
// 	require.NoError(t, err)

// 	verifyReq := &x402types.VerifyRequest{
// 		PaymentHeader: base64.StdEncoding.EncodeToString(headerJSON),
// 		PaymentRequirements: x402types.PaymentRequirements{
// 			PayTo:             toAddr.Hex(),
// 			MaxAmountRequired: "0.001", // Require 0.001 ETH
// 		},
// 	}

// 	result, err := client.VerifyPayment(ctx, verifyReq)
// 	require.NoError(t, err)

// 	t.Logf("❌ Insufficient payment detected:")
// 	t.Logf("   Valid: %v", result.IsValid)
// 	t.Logf("   Reason: %s", result.InvalidReason)

// 	assert.False(t, result.IsValid)
// 	assert.Contains(t, result.InvalidReason, "insufficient payment")
// }

// func TestEthereumClient_WrongRecipient(t *testing.T) {
// 	client, err := NewEthereumClient(anvilRPC, big.NewInt(anvilChainID), "ETH")
// 	require.NoError(t, err)
// 	defer client.Close()

// 	ctx := context.Background()

// 	privateKey, err := crypto.HexToECDSA(testPrivateKey)
// 	require.NoError(t, err)

// 	fromAddr := crypto.PubkeyToAddress(privateKey.PublicKey)
// 	wrongRecipient := common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")

// 	nonce, err := client.client.PendingNonceAt(ctx, fromAddr)
// 	require.NoError(t, err)

// 	amount := big.NewInt(2e15)
// 	gasPrice := big.NewInt(1e9)

// 	tx := types.NewTransaction(nonce, wrongRecipient, amount, 21000, gasPrice, nil)
// 	signer := types.NewEIP155Signer(big.NewInt(anvilChainID))
// 	signedTx, err := types.SignTx(tx, signer, privateKey)
// 	require.NoError(t, err)

// 	txBytes, err := signedTx.MarshalBinary()
// 	require.NoError(t, err)

// 	paymentData := EthereumPaymentData{
// 		Amount:      amount.String(),
// 		Token:       "ETH",
// 		Payer:       fromAddr.Hex(),
// 		Recipient:   wrongRecipient.Hex(),
// 		PaymentType: "native",
// 		TxHash:      signedTx.Hash().Hex(),
// 		SignedTx:    hex.EncodeToString(txBytes),
// 	}

// 	header := EthereumPaymentPayload{
// 		Version: 1,
// 		ChainID: big.NewInt(anvilChainID).String(),
// 		Payment: paymentData,
// 	}

// 	headerJSON, err := json.Marshal(header)
// 	require.NoError(t, err)

// 	verifyReq := &x402types.VerifyRequest{
// 		PaymentHeader: base64.StdEncoding.EncodeToString(headerJSON),
// 		PaymentRequirements: x402types.PaymentRequirements{
// 			PayTo:             recipientAddress, // Expected recipient (different)
// 			MaxAmountRequired: "0.001",
// 		},
// 	}

// 	result, err := client.VerifyPayment(ctx, verifyReq)
// 	require.NoError(t, err)

// 	t.Logf("❌ Wrong recipient detected:")
// 	t.Logf("   Valid: %v", result.IsValid)
// 	t.Logf("   Reason: %s", result.InvalidReason)

// 	assert.False(t, result.IsValid)
// 	assert.Contains(t, result.InvalidReason, "recipient mismatch")
// }

// func TestEthereumClient_ChainIDMismatch(t *testing.T) {
// 	client, err := NewEthereumClient(anvilRPC, big.NewInt(anvilChainID), "ETH")
// 	require.NoError(t, err)
// 	defer client.Close()

// 	ctx := context.Background()

// 	paymentData := EthereumPaymentData{
// 		Amount:      "2000000000000000",
// 		Token:       "ETH",
// 		Payer:       testAddress,
// 		Recipient:   recipientAddress,
// 		PaymentType: "native",
// 	}

// 	// Wrong chain ID (mainnet instead of anvil)
// 	header := EthereumPaymentPayload{
// 		Version: 1,
// 		ChainID: "1",
// 		Payment: paymentData,
// 	}

// 	headerJSON, err := json.Marshal(header)
// 	require.NoError(t, err)

// 	verifyReq := &x402types.VerifyRequest{
// 		PaymentHeader: base64.StdEncoding.EncodeToString(headerJSON),
// 		PaymentRequirements: x402types.PaymentRequirements{
// 			PayTo:             recipientAddress,
// 			MaxAmountRequired: "0.001",
// 		},
// 	}

// 	result, err := client.VerifyPayment(ctx, verifyReq)
// 	require.NoError(t, err)

// 	t.Logf("❌ Chain ID mismatch detected:")
// 	t.Logf("   Valid: %v", result.IsValid)
// 	t.Logf("   Reason: %s", result.InvalidReason)

// 	assert.False(t, result.IsValid)
// 	assert.Contains(t, result.InvalidReason, "chain ID mismatch")
// }

// // Helper function to wait for transaction receipt
// func waitForReceipt(ctx context.Context, client *EthereumClient, txHash common.Hash, timeout time.Duration) (*types.Receipt, error) {
// 	ctx, cancel := context.WithTimeout(ctx, timeout)
// 	defer cancel()

// 	ticker := time.NewTicker(time.Second)
// 	defer ticker.Stop()

// 	for {
// 		select {
// 		case <-ctx.Done():
// 			return nil, ctx.Err()
// 		case <-ticker.C:
// 			receipt, err := client.client.TransactionReceipt(ctx, txHash)
// 			if err == nil {
// 				return receipt, nil
// 			}
// 		}
// 	}
// }

// // Helper function to generate EIP-3009 signature (for future testing)
// func generateEIP3009Signature(
// 	privateKey *ecdsa.PrivateKey,
// 	tokenAddress common.Address,
// 	from, to common.Address,
// 	value *big.Int,
// 	validAfter, validBefore *big.Int,
// 	nonce [32]byte,
// 	chainID *big.Int,
// ) (v uint8, r, s [32]byte, err error) {

// 	domainSeparator := crypto.Keccak256Hash(
// 		crypto.Keccak256([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")),
// 		crypto.Keccak256([]byte("USD Coin")),
// 		crypto.Keccak256([]byte("2")),
// 		common.LeftPadBytes(chainID.Bytes(), 32),
// 		tokenAddress.Bytes(),
// 	)

// 	typeHash := crypto.Keccak256([]byte(
// 		"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
// 	))

// 	structHash := crypto.Keccak256(
// 		typeHash,
// 		common.LeftPadBytes(from.Bytes(), 32),
// 		common.LeftPadBytes(to.Bytes(), 32),
// 		common.LeftPadBytes(value.Bytes(), 32),
// 		common.LeftPadBytes(validAfter.Bytes(), 32),
// 		common.LeftPadBytes(validBefore.Bytes(), 32),
// 		nonce[:],
// 	)

// 	digest := crypto.Keccak256(
// 		[]byte("\x19\x01"),
// 		domainSeparator.Bytes(),
// 		structHash,
// 	)

// 	signature, err := crypto.Sign(digest, privateKey)
// 	if err != nil {
// 		return 0, [32]byte{}, [32]byte{}, err
// 	}

// 	copy(r[:], signature[0:32])
// 	copy(s[:], signature[32:64])
// 	v = signature[64] + 27

// 	return v, r, s, nil
// }
