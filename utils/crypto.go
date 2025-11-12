package utils

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// EIP712Domain represents the EIP-712 domain
type EIP712Domain struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	ChainId           *big.Int `json:"chainId"`
	VerifyingContract common.Address `json:"verifyingContract"`
}

// VerifyEIP712Signature verifies an EIP-712 signature
func VerifyEIP712Signature(typedData apitypes.TypedData, signature string, expectedSigner common.Address) (bool, error) {
	// Remove 0x prefix if present
	signature = strings.TrimPrefix(signature, "0x")
	
	// Decode signature
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}
	
	// Ensure signature is the correct length (65 bytes)
	if len(sigBytes) != 65 {
		return false, fmt.Errorf("signature must be 65 bytes, got %d", len(sigBytes))
	}
	
	// Adjust recovery ID for Ethereum
	if sigBytes[64] >= 27 {
		sigBytes[64] -= 27
	}
	
	// Hash the typed data
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return false, fmt.Errorf("failed to hash domain: %w", err)
	}
	
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return false, fmt.Errorf("failed to hash typed data: %w", err)
	}
	
	// Create the final hash
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	hash := crypto.Keccak256Hash(rawData)
	
	// Recover public key
	pubKey, err := crypto.SigToPub(hash.Bytes(), sigBytes)
	if err != nil {
		return false, fmt.Errorf("failed to recover public key: %w", err)
	}
	
	// Get address from public key
	recoveredAddress := crypto.PubkeyToAddress(*pubKey)
	
	return recoveredAddress == expectedSigner, nil
}

// RecoverAddressFromSignature recovers the Ethereum address from a signature
func RecoverAddressFromSignature(hash []byte, signature string) (common.Address, error) {
	// Remove 0x prefix if present
	signature = strings.TrimPrefix(signature, "0x")
	
	// Decode signature
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to decode signature: %w", err)
	}
	
	// Ensure signature is the correct length
	if len(sigBytes) != 65 {
		return common.Address{}, fmt.Errorf("signature must be 65 bytes, got %d", len(sigBytes))
	}
	
	// Adjust recovery ID for Ethereum
	if sigBytes[64] >= 27 {
		sigBytes[64] -= 27
	}
	
	// Recover public key
	pubKey, err := crypto.SigToPub(hash, sigBytes)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to recover public key: %w", err)
	}
	
	return crypto.PubkeyToAddress(*pubKey), nil
}

// PrivateKeyFromHex creates a private key from hex string
func PrivateKeyFromHex(hexKey string) (*ecdsa.PrivateKey, error) {
	// Remove 0x prefix if present
	hexKey = strings.TrimPrefix(hexKey, "0x")
	
	return crypto.HexToECDSA(hexKey)
}

// AddressFromPrivateKey derives the Ethereum address from a private key
func AddressFromPrivateKey(privateKey *ecdsa.PrivateKey) common.Address {
	return crypto.PubkeyToAddress(privateKey.PublicKey)
}

// SignHash signs a hash with the given private key
func SignHash(hash []byte, privateKey *ecdsa.PrivateKey) (string, error) {
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign hash: %w", err)
	}
	
	return hexutil.Encode(signature), nil
}

// ValidateAddress checks if a string is a valid Ethereum address
func ValidateAddress(address string) bool {
	return common.IsHexAddress(address)
}

// NormalizeAddress ensures an address is properly checksummed
func NormalizeAddress(address string) string {
	if !common.IsHexAddress(address) {
		return ""
	}
	return common.HexToAddress(address).Hex()
}

// Personal message signing (for Ethereum personal_sign)
func SignPersonalMessage(message string, privateKey *ecdsa.PrivateKey) (string, error) {
	hash := accounts.TextHash([]byte(message))
	return SignHash(hash, privateKey)
}

// Verify personal message signature
func VerifyPersonalMessage(message, signature string, expectedAddress common.Address) (bool, error) {
	hash := accounts.TextHash([]byte(message))
	recoveredAddr, err := RecoverAddressFromSignature(hash, signature)
	if err != nil {
		return false, err
	}
	
	return recoveredAddr == expectedAddress, nil
}