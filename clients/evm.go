package clients

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type TypeEntry struct {
	Name string
	Type string
}

type TypedDataDomain struct {
	Name              string      `json:"name"`
	Version           string      `json:"version"`
	ChainId           interface{} `json:"chainId"`
	VerifyingContract string      `json:"verifyingContract"`
}

type TypedData struct {
	Types       map[string][]TypeEntry `json:"types"`
	PrimaryType string                 `json:"primaryType"`
	Domain      TypedDataDomain        `json:"domain"`
	Message     map[string]interface{} `json:"message"`
}

// TypeHash returns keccak256(EncodeType(typeName))
func TypeHash(typeName string, fields []TypeEntry, types map[string][]TypeEntry) []byte {
	return keccak([]byte(EncodeType(typeName, fields, types)))
}

// ---------- EIP-712 encoding helpers ----------
func EncodeType(typeName string, fields []TypeEntry, types map[string][]TypeEntry) string {
	var b strings.Builder
	b.WriteString(typeName)
	b.WriteRune('(')
	for i, f := range fields {
		if i > 0 {
			b.WriteRune(',')
		}
		b.WriteString(f.Type)
		b.WriteRune(' ')
		b.WriteString(f.Name)
	}
	b.WriteRune(')')
	// no nested deps used in this example
	return b.String()
}

// HashStruct computes keccak256(abi.encode(typeHash, fields...))
// IMPORTANT: returns bytes32 (slice) — caller should convert to [32]byte when pushing to ABI values.
func HashStruct(typeName string, data map[string]interface{}, types map[string][]TypeEntry) ([]byte, error) {
	fields := types[typeName]

	// Build abi.Arguments and values
	args := abi.Arguments{}
	values := make([]interface{}, 0, len(fields)+1)

	// typeHash as first argument (bytes32) -> convert to [32]byte and append value later
	args = append(args, abi.Argument{Type: mustABIType("bytes32")})
	typeHash := TypeHash(typeName, fields, types)
	var typeHashArr [32]byte
	copy(typeHashArr[:], typeHash)
	values = append(values, typeHashArr)

	for _, f := range fields {
		switch f.Type {
		case "address":
			args = append(args, abi.Argument{Type: mustABIType("address")})
			v, ok := data[f.Name].(string)
			if !ok {
				return nil, fmt.Errorf("field %s not a string", f.Name)
			}
			values = append(values, common.HexToAddress(v))
		case "uint256":
			args = append(args, abi.Argument{Type: mustABIType("uint256")})
			var s string
			switch vv := data[f.Name].(type) {
			case string:
				s = vv
			default:
				j, _ := json.Marshal(vv)
				s = strings.Trim(string(j), `"`)
			}
			bi, ok := new(big.Int).SetString(s, 10)
			if !ok {
				return nil, fmt.Errorf("bad uint256 value for %s", f.Name)
			}
			values = append(values, bi)
		case "bytes32":
			args = append(args, abi.Argument{Type: mustABIType("bytes32")})
			v, ok := data[f.Name].(string)
			if !ok {
				return nil, fmt.Errorf("field %s not a string", f.Name)
			}
			b, err := hex.DecodeString(strings.TrimPrefix(v, "0x"))
			if err != nil {
				return nil, err
			}
			if len(b) != 32 {
				return nil, fmt.Errorf("bytes32 field %s wrong len=%d", f.Name, len(b))
			}
			var arr [32]byte
			copy(arr[:], b)
			values = append(values, arr)
		case "string":
			// per EIP-712, hash string and treat as bytes32
			args = append(args, abi.Argument{Type: mustABIType("bytes32")})
			var s string
			switch vv := data[f.Name].(type) {
			case string:
				s = vv
			default:
				j, _ := json.Marshal(vv)
				s = strings.Trim(string(j), `"`)
			}
			h := keccak([]byte(s))
			var arr [32]byte
			copy(arr[:], h)
			values = append(values, arr)
		default:
			return nil, fmt.Errorf("unsupported field type %s", f.Type)
		}
	}

	// abi.encode (not packed) — arguments must match values types exactly
	packed, err := args.Pack(values...)
	if err != nil {
		return nil, err
	}
	return keccak(packed), nil
}

// TypedDataHash produces final digest keccak256("\x19\x01" || domainSeparator || messageHash)
func TypedDataHash(domain TypedDataDomain, primaryType string, message map[string]interface{}, t map[string][]TypeEntry) ([]byte, error) {
	networkName, ok := domain.ChainId.(string)
	if !ok {
		return nil, fmt.Errorf("expected chain-name as string")
	}

	chainId, found := EVMNetworkToChainId[networkName]
	if !found {
		return nil, fmt.Errorf("unsupported network %s", networkName)
	}
	dmap := map[string]interface{}{
		"name":              domain.Name,
		"version":           domain.Version,
		"chainId":           fmt.Sprintf("%d", chainId),
		"verifyingContract": domain.VerifyingContract,
	}
	domainFields := []TypeEntry{
		{"name", "string"},
		{"version", "string"},
		{"chainId", "uint256"},
		{"verifyingContract", "address"},
	}
	t["EIP712Domain"] = domainFields

	domainHash, err := HashStruct("EIP712Domain", dmap, t)
	if err != nil {
		return nil, err
	}
	msgHash, err := HashStruct(primaryType, message, t)
	if err != nil {
		return nil, err
	}
	outer := bytes.Join([][]byte{{0x19}, {0x01}, domainHash, msgHash}, nil)
	digest := keccak(outer)

	return digest, nil
}

func keccak(b ...[]byte) []byte {
	return crypto.Keccak256(bytes.Join(b, nil))
}
