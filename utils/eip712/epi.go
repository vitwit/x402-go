package eip712

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// EIP712Domain mirrors the JSON domain you already have in types.
type EIP712Domain struct {
	Name              string // e.g. "MyToken"
	Version           string // e.g. "1"
	ChainId           string // decimal string
	VerifyingContract string // hex address "0x..."
}

// --- Type hashes (keccak256 of the type signature strings) ---
var (
	// PERMIT_TYPE = "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
	permitTypeHash = crypto.Keccak256Hash([]byte("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"))

	// TRANSFER_WITH_AUTH_TYPE = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
	transferAuthTypeHash = crypto.Keccak256Hash([]byte("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"))

	// EIP712Domain type string - note ordering matters
	domainTypeHash = crypto.Keccak256Hash([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
)

// Helpers ---------------------------------------------------------------------

// keccak256ABI packs a set of byte slices exactly as abi.encodePacked would,
// but here we simply concat the 32-byte words (already hashed or padded) needed
// for EIP-712 encodings (domain and struct hashing).
func keccak256ABI(parts ...[]byte) common.Hash {
	joined := []byte{}
	for _, p := range parts {
		joined = append(joined, p...)
	}
	return crypto.Keccak256Hash(joined)
}

// padLeft32 returns a 32-byte right-aligned representation of the given big.Int
func padLeft32(i *big.Int) []byte {
	b := i.Bytes()
	if len(b) > 32 {
		// shouldn't happen for uint256 inputs in normal use
		b = b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// addressTo32 right-pads an address into 32 bytes (left-padding with zeros)
func addressTo32(a common.Address) []byte {
	out := make([]byte, 32)
	copy(out[12:], a.Bytes()) // address fits in last 20 bytes
	return out
}

// stringToBig converts decimal string -> *big.Int
func stringToBig(s string) (*big.Int, error) {
	n := new(big.Int)
	_, ok := n.SetString(s, 10)
	if !ok {
		return nil, errors.New("invalid decimal integer string")
	}
	return n, nil
}

// HexToBytes32 converts hex (with/without 0x) to 32-byte array (for nonce in EIP-3009)
func HexToBytes32(hexStr string) ([32]byte, error) {
	var out [32]byte
	if len(hexStr) >= 2 && hexStr[0:2] == "0x" {
		hexStr = hexStr[2:]
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return out, err
	}
	if len(b) > 32 {
		// take last 32 bytes (similar to left-truncate) — but prefer caller to pass exactly 32
		copy(out[:], b[len(b)-32:])
		return out, nil
	}
	copy(out[32-len(b):], b)
	return out, nil
}

// EIP712 Domain Separator -----------------------------------------------------

// DomainSeparator builds the domainSeparator hash per EIP-712:
// keccak256(abi.encode(domainTypeHash, keccak256(name), keccak256(version), chainId, verifyingContract))
func DomainSeparator(d EIP712Domain) (common.Hash, error) {
	if d.Name == "" || d.Version == "" || d.ChainId == "" || d.VerifyingContract == "" {
		return common.Hash{}, errors.New("incomplete domain")
	}

	nameHash := crypto.Keccak256Hash([]byte(d.Name))
	versionHash := crypto.Keccak256Hash([]byte(d.Version))

	chainId, err := stringToBig(d.ChainId)
	if err != nil {
		return common.Hash{}, err
	}

	verifying := common.HexToAddress(d.VerifyingContract)

	// abi.encode(domainTypeHash, nameHash, versionHash, chainId, verifyingContract)
	// each param must be 32-bytes: typehash (32) + nameHash(32) + versionHash(32) + chainId(32) + verifyingContract(32)
	parts := [][]byte{
		domainTypeHash.Bytes(),
		nameHash.Bytes(),
		versionHash.Bytes(),
		padLeft32(chainId),
		addressTo32(verifying),
	}
	return keccak256ABI(parts...), nil
}

// EIP-2612 Permit struct hash ------------------------------------------------

// HashPermitStruct computes keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline))
func HashPermitStruct(owner, spender common.Address, value, nonce, deadline *big.Int) common.Hash {
	parts := [][]byte{
		permitTypeHash.Bytes(),
		addressTo32(owner),
		addressTo32(spender),
		padLeft32(value),
		padLeft32(nonce),
		padLeft32(deadline),
	}
	return keccak256ABI(parts...)
}

// EIP-3009 TransferWithAuthorization struct hash -----------------------------

// HashTransferWithAuthorizationStruct computes keccak256(
//
//	abi.encode(TRANSFER_WITH_AUTH_TYPEHASH, from, to, value, validAfter, validBefore, nonceBytes32)
//
// )
func HashTransferWithAuthorizationStruct(from, to common.Address, value, validAfter, validBefore *big.Int, nonce [32]byte) common.Hash {
	parts := [][]byte{
		transferAuthTypeHash.Bytes(),
		addressTo32(from),
		addressTo32(to),
		padLeft32(value),
		padLeft32(validAfter),
		padLeft32(validBefore),
		nonce[:], // already 32 bytes
	}
	return keccak256ABI(parts...)
}

// Final EIP-712 Digest -------------------------------------------------------

// TypedDataHash returns the final EIP-712 hash/digest to be signed/recovered:
//
//	keccak256("\x19\x01", domainSeparator, structHash)
func TypedDataHash(domainSeparator, structHash common.Hash) common.Hash {
	prefix := []byte{0x19, 0x01}
	return crypto.Keccak256Hash(append(append(prefix, domainSeparator.Bytes()...), structHash.Bytes()...))
}

// Convenience high-level helpers ---------------------------------------------

// BuildPermitDigest builds the EIP-712 digest for EIP-2612 permit.
// Inputs for value/nonce/deadline are decimal strings (as you store in JSON).
func BuildPermitDigest(domain EIP712Domain, ownerHex, spenderHex, valueDec, nonceDec, deadlineDec string) (common.Hash, error) {
	domainSep, err := DomainSeparator(domain)
	if err != nil {
		return common.Hash{}, err
	}
	owner := common.HexToAddress(ownerHex)
	spender := common.HexToAddress(spenderHex)

	value, err := stringToBig(valueDec)
	if err != nil {
		return common.Hash{}, err
	}
	nonce, err := stringToBig(nonceDec)
	if err != nil {
		return common.Hash{}, err
	}
	deadline, err := stringToBig(deadlineDec)
	if err != nil {
		return common.Hash{}, err
	}

	structHash := HashPermitStruct(owner, spender, value, nonce, deadline)
	return TypedDataHash(domainSep, structHash), nil
}

// BuildTransferWithAuthDigest builds the EIP-712 digest for EIP-3009 transferWithAuthorization.
// validAfter/validBefore are decimal strings; nonceHex is hex (0x...) or plain hex.
func BuildTransferWithAuthDigest(domain EIP712Domain, fromHex, toHex, valueDec, validAfterDec, validBeforeDec, nonceHex string) (common.Hash, error) {
	domainSep, err := DomainSeparator(domain)
	if err != nil {
		return common.Hash{}, err
	}
	from := common.HexToAddress(fromHex)
	to := common.HexToAddress(toHex)

	value, err := stringToBig(valueDec)
	if err != nil {
		return common.Hash{}, err
	}
	validAfter, err := stringToBig(validAfterDec)
	if err != nil {
		return common.Hash{}, err
	}
	validBefore, err := stringToBig(validBeforeDec)
	if err != nil {
		return common.Hash{}, err
	}
	nonceBytes, err := HexToBytes32(nonceHex)
	if err != nil {
		return common.Hash{}, err
	}

	structHash := HashTransferWithAuthorizationStruct(from, to, value, validAfter, validBefore, nonceBytes)
	return TypedDataHash(domainSep, structHash), nil
}

// RecoverSigner recovers the Ethereum address that signed the given digest.
// sig must be 65 bytes (R||S||V). V may be 0/1 or 27/28 — we normalize it.
func RecoverSigner(digest common.Hash, sig []byte) (common.Address, error) {
	if len(sig) != 65 {
		return common.Address{}, errors.New("signature must be 65 bytes")
	}

	// copy to avoid mutating caller slice
	s := make([]byte, 65)
	copy(s, sig)

	// normalize V to 27/28 if it's 0/1
	if s[64] < 27 {
		s[64] += 27
	}

	pubKey, err := crypto.SigToPub(digest.Bytes(), s)
	if err != nil {
		return common.Address{}, fmt.Errorf("sig to pub failed: %w", err)
	}
	return crypto.PubkeyToAddress(*pubKey), nil
}

type EIP3009Authorization struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

type EthereumPermitPayload struct {
	Type    string           `json:"type"` // "permit"
	Token   string           `json:"token"`
	Domain  EIP712Domain     `json:"domain"`
	Message EIP2612PermitMsg `json:"message"`
}

type EIP2612PermitMsg struct {
	Owner    string `json:"owner"`
	Spender  string `json:"spender"`
	Value    string `json:"value"`
	Nonce    string `json:"nonce"`
	Deadline string `json:"deadline"`
}

type EthereumTransferWithAuthorizationPayload struct {
	Type    string               `json:"type"` // "transferWithAuthorization"
	Token   string               `json:"token"`
	Domain  EIP712Domain         `json:"domain"`
	Message EIP3009Authorization `json:"message"`
}

const EIP3009Type = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"

var EIP3009TypeHash = crypto.Keccak256Hash([]byte(EIP3009Type))

func HashEIP3009(msg EIP3009Authorization) common.Hash {
	return crypto.Keccak256Hash(
		EIP3009TypeHash.Bytes(),
		addressTo32(common.HexToAddress(msg.From)),
		addressTo32(common.HexToAddress(msg.To)),
		pad32(common.LeftPadBytes(common.FromHex(msg.Value), 32)),
		pad32(common.LeftPadBytes(common.FromHex(msg.ValidAfter), 32)),
		pad32(common.LeftPadBytes(common.FromHex(msg.ValidBefore), 32)),
		common.HexToHash(msg.Nonce).Bytes(),
	)
}

func pad32(b []byte) []byte {
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
