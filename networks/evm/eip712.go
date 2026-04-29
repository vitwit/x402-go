package evm

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// TransferWithAuthorization EIP-712 type hash.
// keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
var transferWithAuthorizationTypeHash = crypto.Keccak256Hash(
	[]byte("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"),
)

// eip712DomainTypeHash for tokens that follow standard USDC domain.
// keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
var eip712DomainTypeHash = crypto.Keccak256Hash(
	[]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
)

// domainSeparator computes the EIP-712 domain separator for a token contract.
func domainSeparator(tokenName, version string, chainID int64, contractAddr common.Address) common.Hash {
	nameHash := crypto.Keccak256Hash([]byte(tokenName))
	versionHash := crypto.Keccak256Hash([]byte(version))

	uint256T, _ := abi.NewType("uint256", "", nil)
	addressT, _ := abi.NewType("address", "", nil)
	bytes32T, _ := abi.NewType("bytes32", "", nil)

	args := abi.Arguments{
		{Type: bytes32T},
		{Type: bytes32T},
		{Type: bytes32T},
		{Type: uint256T},
		{Type: addressT},
	}

	packed, err := args.Pack(
		eip712DomainTypeHash,
		nameHash,
		versionHash,
		big.NewInt(chainID),
		contractAddr,
	)
	if err != nil {
		panic(fmt.Sprintf("domainSeparator pack: %v", err))
	}
	return crypto.Keccak256Hash(packed)
}

// structHash computes the EIP-712 struct hash for TransferWithAuthorization.
func structHash(from, to common.Address, value *big.Int, validAfter, validBefore int64, nonce [32]byte) common.Hash {
	uint256T, _ := abi.NewType("uint256", "", nil)
	addressT, _ := abi.NewType("address", "", nil)
	bytes32T, _ := abi.NewType("bytes32", "", nil)

	args := abi.Arguments{
		{Type: bytes32T},
		{Type: addressT},
		{Type: addressT},
		{Type: uint256T},
		{Type: uint256T},
		{Type: uint256T},
		{Type: bytes32T},
	}

	packed, err := args.Pack(
		transferWithAuthorizationTypeHash,
		from,
		to,
		value,
		big.NewInt(validAfter),
		big.NewInt(validBefore),
		nonce,
	)
	if err != nil {
		panic(fmt.Sprintf("structHash pack: %v", err))
	}
	return crypto.Keccak256Hash(packed)
}

// hashToSign produces the final EIP-712 digest (the bytes that were signed).
func hashToSign(domain, structH common.Hash) common.Hash {
	return crypto.Keccak256Hash(
		[]byte("\x19\x01"),
		domain[:],
		structH[:],
	)
}

// recoverSigner returns the address that produced sig over digest.
func recoverSigner(digest common.Hash, sig []byte) (common.Address, error) {
	if len(sig) != 65 {
		return common.Address{}, fmt.Errorf("signature must be 65 bytes, got %d", len(sig))
	}
	// Normalise v: Ethereum uses 27/28 but crypto.Sign uses 0/1
	sigCopy := make([]byte, 65)
	copy(sigCopy, sig)
	if sigCopy[64] >= 27 {
		sigCopy[64] -= 27
	}
	pub, err := crypto.SigToPub(digest[:], sigCopy)
	if err != nil {
		return common.Address{}, fmt.Errorf("recover public key: %w", err)
	}
	return crypto.PubkeyToAddress(*pub), nil
}

// hexToBytes32 converts a 0x-prefixed 32-byte hex string to [32]byte.
func hexToBytes32(s string) ([32]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, err
	}
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

// hexToSignature converts a 0x-prefixed 65-byte hex string to []byte.
func hexToSignature(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 65 {
		return nil, fmt.Errorf("expected 65 bytes, got %d", len(b))
	}
	return b, nil
}
