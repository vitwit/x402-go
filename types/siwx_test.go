package types_test

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gagliardetto/solana-go"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/vitwit/x402"
	"github.com/vitwit/x402/types"
)

func TestSIWxVerification_EVM(t *testing.T) {
	// Initialize X402 (this wires the helpers)
	x402.New(nil)

	// 1. Setup EVM account
	privKey, err := crypto.GenerateKey()
	assert.NoError(t, err)
	publicKey := privKey.Public().(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*publicKey).Hex()

	msg := &types.SIWxMessage{
		Domain:    "localhost",
		Address:   address,
		URI:       "http://localhost:8080",
		Version:   "1",
		ChainID:   "eip155:1",
		Nonce:     "nonce123",
		IssuedAt:  time.Now(),
		Statement: "Sign in to x402",
	}

	// 2. Sign the message
	messageToSign := msg.String()
	hash := accounts.TextHash([]byte(messageToSign))
	sigBytes, err := crypto.Sign(hash, privKey)
	assert.NoError(t, err)

	// Adjust recovery ID for Ethereum
	sigBytes[64] += 27
	signature := hexutil.Encode(sigBytes)

	// 3. Verify
	valid, err := msg.Verify(signature)
	assert.NoError(t, err)
	assert.True(t, valid, "SIWx verification failed for EVM")
}

func TestSIWxVerification_Solana(t *testing.T) {
	// Initialize X402
	x402.New(nil)

	// 1. Setup Solana account
	account := solana.NewWallet()
	address := account.PublicKey().String()

	msg := &types.SIWxMessage{
		Domain:    "localhost",
		Address:   address,
		URI:       "http://localhost:8080",
		Version:   "1",
		ChainID:   "solana:devnet",
		Nonce:     "nonce123",
		IssuedAt:  time.Now(),
		Statement: "Sign in to x402",
	}

	// 2. Sign the message
	messageToSign := msg.String()
	sig, err := account.PrivateKey.Sign([]byte(messageToSign))
	assert.NoError(t, err)
	signature := base58.Encode(sig[:])

	// 3. Verify
	valid, err := msg.Verify(signature)
	assert.NoError(t, err)
	assert.True(t, valid, "SIWx verification failed for Solana")
}

func TestSIWxMessage_String(t *testing.T) {
	issuedAt := time.Date(2024, 3, 13, 10, 0, 0, 0, time.UTC)
	msg := &types.SIWxMessage{
		Domain:    "example.com",
		Address:   "0x123",
		Statement: "Hello world",
		URI:       "https://example.com/login",
		Version:   "1",
		ChainID:   "eip155:1",
		Nonce:     "n0nc3",
		IssuedAt:  issuedAt,
	}

	expected := "example.com wants you to sign in with your Ethereum account:\n0x123\n\nHello world\n\nURI: https://example.com/login\nVersion: 1\nChain ID: eip155:1\nNonce: n0nc3\nIssued At: 2024-03-13T10:00:00Z"
	assert.Equal(t, expected, msg.String())
}
