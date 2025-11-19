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

// normalizeSigFlexible accepts 0xhex signature that may be 64 (EIP-2098) or 65 bytes; returns 65 bytes (r|s|v)
func normalizeSigFlexible(sigHex string) ([]byte, error) {
	s := strings.TrimPrefix(sigHex, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case 65:
		return b, nil
	case 64: // compact form r||vs (EIP-2098)
		r := b[:32]
		vs := b[32:64]
		last := vs[31]
		v := byte(27)
		if last&0x80 != 0 {
			v = 28
		}
		vs[31] = last & 0x7F
		out := make([]byte, 65)
		copy(out[0:32], r)
		copy(out[32:64], vs)
		out[64] = v
		return out, nil
	default:
		return nil, fmt.Errorf("unexpected signature length: %d", len(b))
	}
}

// encodePacked implements a simple packed encoder for the subset we need.
// supported types: "bytes32", "address", "uint256", "bytes1"
func encodePacked(types []string, values []interface{}) ([]byte, error) {
	if len(types) != len(values) {
		return nil, fmt.Errorf("encodePacked: types/values length mismatch")
	}
	var out []byte
	for i, t := range types {
		b, err := packSingle(t, values[i])
		if err != nil {
			return nil, fmt.Errorf("encodePacked: field %d type %s: %w", i, t, err)
		}
		out = append(out, b...)
	}
	return out, nil
}

func mustHexToBytes(s string) ([]byte, error) {
	if strings.HasPrefix(s, "0x") {
		s = s[2:]
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

func packSingle(t string, v interface{}) ([]byte, error) {
	switch t {
	case "bytes32":
		// accept []byte(32), [32]byte, string hex or keccak result
		switch vv := v.(type) {
		case []byte:
			// if it's hash bytes (len 32) use it
			if len(vv) == 32 {
				return vv, nil
			}
			if len(vv) < 32 {
				p := make([]byte, 32)
				copy(p[32-len(vv):], vv)
				return p, nil
			}
			return nil, fmt.Errorf("bytes32: too long %d", len(vv))
		case [32]byte:
			b := vv[:]
			return b, nil
		case string:
			// maybe 0x... or raw text (not expected except for keccak outputs)
			// if looks like hex -> decode
			if strings.HasPrefix(vv, "0x") {
				b, err := mustHexToBytes(vv)
				if err != nil {
					return nil, err
				}
				if len(b) != 32 {
					// left-pad
					if len(b) > 32 {
						return nil, fmt.Errorf("bytes32 hex too long: %d", len(b))
					}
					p := make([]byte, 32)
					copy(p[32-len(b):], b)
					return p, nil
				}
				return b, nil
			}
			// otherwise treat as raw string -> hash it and return 32 bytes
			h := crypto.Keccak256([]byte(vv))
			return h, nil
		default:
			return nil, fmt.Errorf("bytes32: unsupported input type %T", v)
		}
	case "address":
		switch vv := v.(type) {
		case string:
			addr := common.HexToAddress(vv)
			return addr.Bytes(), nil // 20 bytes
		case common.Address:
			return vv.Bytes(), nil
		default:
			return nil, fmt.Errorf("address: unsupported input %T", v)
		}
	case "uint256":
		// represent as 32-byte big-endian
		switch vv := v.(type) {
		case string:
			bi := new(big.Int)
			_, ok := bi.SetString(vv, 10)
			if !ok {
				return nil, fmt.Errorf("uint256: invalid decimal string %s", vv)
			}
			return bigIntTo32(bi), nil
		case *big.Int:
			return bigIntTo32(vv), nil
		case int:
			return bigIntTo32(big.NewInt(int64(vv))), nil
		case int64:
			return bigIntTo32(big.NewInt(vv)), nil
		case float64:
			// if coming from JSON number
			bi := big.NewInt(int64(vv))
			return bigIntTo32(bi), nil
		default:
			// try marshal->string
			b, _ := json.Marshal(vv)
			s := strings.Trim(string(b), `"`)
			bi := new(big.Int)
			_, ok := bi.SetString(s, 10)
			if ok {
				return bigIntTo32(bi), nil
			}
			return nil, fmt.Errorf("uint256: unsupported type %T", v)
		}
	case "bytes1":
		switch vv := v.(type) {
		case string:
			// expect "0x19" etc
			b, err := mustHexToBytes(vv)
			if err != nil {
				return nil, err
			}
			if len(b) != 1 {
				// if given as "0x19" decode ok; else try first byte of string
				if len(b) > 1 {
					return []byte{b[0]}, nil
				}
				return nil, fmt.Errorf("bytes1 length != 1")
			}
			return b, nil
		default:
			return nil, fmt.Errorf("bytes1 unsupported %T", v)
		}
	default:
		return nil, fmt.Errorf("packSingle: unsupported packed type: %s", t)
	}
}

func bigIntTo32(b *big.Int) []byte {
	// return 32-byte big-endian
	out := make([]byte, 32)
	if b == nil {
		return out
	}
	// get absolute bytes (big-endian)
	bb := b.Bytes()
	if len(bb) > 32 {
		// truncate? but ideally should error
		return bb[len(bb)-32:]
	}
	copy(out[32-len(bb):], bb)
	return out
}
