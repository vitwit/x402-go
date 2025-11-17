package main

// import (
// 	"crypto/ecdsa"
// 	"encoding/hex"
// 	"math/big"
// 	"testing"
// 	"time"

// 	"github.com/ethereum/go-ethereum/common"
// 	"github.com/ethereum/go-ethereum/crypto"
// )

// func mustKey(hexKey string, t *testing.T) *ecdsa.PrivateKey {
// 	k, err := crypto.HexToECDSA(hexKey)
// 	if err != nil {
// 		t.Fatalf("failed to load key: %v", err)
// 	}
// 	return k
// }

// func TestFormatUSDC(t *testing.T) {
// 	amt := big.NewInt(123456789)
// 	expected := "123.456789"

// 	got := formatUSDC(amt)
// 	if got != expected {
// 		t.Fatalf("expected %s, got %s", expected, got)
// 	}
// }

// func TestSignEIP3009(t *testing.T) {
// 	priv := mustKey("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", t)

// 	from := crypto.PubkeyToAddress(priv.PublicKey)
// 	to := common.HexToAddress("0x1111111111111111111111111111111111111111")
// 	token := common.HexToAddress("0x2222222222222222222222222222222222222222")
// 	chainID := big.NewInt(1337)

// 	value := big.NewInt(50_000_000)
// 	validAfter := big.NewInt(0)
// 	validBefore := big.NewInt(time.Now().Add(1 * time.Hour).Unix())

// 	var nonce [32]byte
// 	copy(nonce[:], crypto.Keccak256([]byte("test-nonce-12345")))

// 	v, r, s, err := signEIP3009(
// 		priv,
// 		token,
// 		from,
// 		to,
// 		value,
// 		validAfter,
// 		validBefore,
// 		nonce,
// 		chainID,
// 	)
// 	if err != nil {
// 		t.Fatalf("signEIP3009 returned error: %v", err)
// 	}

// 	if v != 27 && v != 28 {
// 		t.Fatalf("invalid v value: %d", v)
// 	}

// 	// Validate r and s are non-zero
// 	if r == ([32]byte{}) {
// 		t.Fatal("r is zero")
// 	}
// 	if s == ([32]byte{}) {
// 		t.Fatal("s is zero")
// 	}

// 	t.Logf("v = %d", v)
// 	t.Logf("r = 0x%s", hex.EncodeToString(r[:]))
// 	t.Logf("s = 0x%s", hex.EncodeToString(s[:]))
// }

// func TestEIP3009SignatureUniqueness(t *testing.T) {
// 	priv := mustKey("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", t)

// 	from := crypto.PubkeyToAddress(priv.PublicKey)
// 	to := common.HexToAddress("0x3333333333333333333333333333333333333333")
// 	token := common.HexToAddress("0x4444444444444444444444444444444444444444")
// 	chainID := big.NewInt(1337)

// 	value := big.NewInt(10_000_000)
// 	validAfter := big.NewInt(0)
// 	validBefore := big.NewInt(time.Now().Add(2 * time.Hour).Unix())

// 	var nonce1, nonce2 [32]byte
// 	copy(nonce1[:], crypto.Keccak256([]byte("nonce1")))
// 	copy(nonce2[:], crypto.Keccak256([]byte("nonce2")))

// 	_, r1, s1, _ := signEIP3009(priv, token, from, to, value, validAfter, validBefore, nonce1, chainID)
// 	_, r2, s2, _ := signEIP3009(priv, token, from, to, value, validAfter, validBefore, nonce2, chainID)

// 	if r1 == r2 && s1 == s2 {
// 		t.Fatal("different nonces should produce different signatures")
// 	}
// }

// func TestEIP3009DigestChangesOnValue(t *testing.T) {
// 	priv := mustKey("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", t)

// 	from := crypto.PubkeyToAddress(priv.PublicKey)
// 	to := common.HexToAddress("0x5555555555555555555555555555555555555555")
// 	token := common.HexToAddress("0x6666666666666666666666666666666666666666")
// 	chainID := big.NewInt(1337)

// 	var nonce [32]byte
// 	copy(nonce[:], crypto.Keccak256([]byte("same-nonce")))

// 	validAfter := big.NewInt(0)
// 	validBefore := big.NewInt(time.Now().Add(3 * time.Hour).Unix())

// 	// Sign with 10 USDC
// 	_, r1, s1, _ := signEIP3009(
// 		priv,
// 		token,
// 		from,
// 		to,
// 		big.NewInt(10_000_000),
// 		validAfter,
// 		validBefore,
// 		nonce,
// 		chainID,
// 	)

// 	// Sign with 20 USDC
// 	_, r2, s2, _ := signEIP3009(
// 		priv,
// 		token,
// 		from,
// 		to,
// 		big.NewInt(20_000_000),
// 		validAfter,
// 		validBefore,
// 		nonce,
// 		chainID,
// 	)

// 	if r1 == r2 && s1 == s2 {
// 		t.Fatal("same nonce with different values should produce different signatures")
// 	}
// }
