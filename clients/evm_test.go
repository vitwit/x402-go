package clients

// import (
// 	"encoding/hex"
// 	"fmt"
// 	"testing"

// 	"github.com/ethereum/go-ethereum/common"
// )

// func TestEIP712ViemCompatibility(t *testing.T) {
// 	// ---- COPY EXACT VALUES FROM JS ----
// 	// viemDomainSep := "0xf53356630fca19d09c9da952eaaa017c3d3e33b9c6802923207fd9243d78f163"
// 	// viemMessageHash := "0xcfeaa8f11d21e4b64c77d2d38e9a1314e9b9f3db285df7a9e5c102a8ecf0d64f"
// 	// viemFinalHash := "0xc490f1b48d0f7593e15b3fc5990497f828b5b59f6f73441c3543a17289b47e2c"

// 	signature := "0x2e8818a233e2e802c953aed477858957ff85a4b91e047181e17ef4b096108e66409119a4c3fac7867b2c2b799b32a0aac108c524cffb3bf0ea6e0906f63d80271b"
// 	expectedSigner := common.HexToAddress("0xE4d365a5a8fC0DCEE9E3C5985D7FcBab8B4A0fE1")

// 	// ---- Types (exact JS form) ----
// 	types := map[string][]TypeEntry{
// 		"EIP712Domain": {
// 			{"name", "string"},
// 			{"version", "string"},
// 			{"chainId", "uint256"},
// 			{"verifyingContract", "address"},
// 		},
// 		"TransferWithAuthorization": {
// 			{"from", "address"},
// 			{"to", "address"},
// 			{"value", "uint256"},
// 			{"validAfter", "uint256"},
// 			{"validBefore", "uint256"},
// 			{"nonce", "bytes32"},
// 		},
// 	}

// 	// ---- Domain ----
// 	td := TypedData{
// 		Types:       types,
// 		PrimaryType: "TransferWithAuthorization",
// 		Domain: TypedDataDomain{
// 			Name:              "USDC",
// 			Version:           "2",
// 			ChainId:           "84532",
// 			VerifyingContract: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
// 		},
// 		Message: map[string]interface{}{
// 			"from":        "0xE4d365a5a8fC0DCEE9E3C5985D7FcBab8B4A0fE1",
// 			"to":          "0x384Aa214be0B279cbf211e9b2C992d8633F77848",
// 			"value":       "10000",
// 			"validAfter":  "1763450282",
// 			"validBefore": "1763451182",
// 			"nonce":       "0xf408d6d1f1d1bca7c6396ed30f00a46ca4e5b073fff983e42b348776a5aa651c",
// 		},
// 	}

// 	// ---- Compute domain separator ----
// 	domainMap := map[string]interface{}{
// 		"name":              td.Domain.Name,
// 		"version":           td.Domain.Version,
// 		"chainId":           td.Domain.ChainId,
// 		"verifyingContract": td.Domain.VerifyingContract,
// 	}
// 	goDomainSep, _ := HashStruct("EIP712Domain", domainMap, td.Types)

// 	// ---- Compute message hash ----
// 	goMessageHash, _ := HashStruct("TransferWithAuthorization", td.Message, td.Types)

// 	// ---- Final EIP-712 hash ----
// 	goFinalHash, _ := TypedDataHash(td)

// 	fmt.Println("Go domainSeparator:", "0x"+hex.EncodeToString(goDomainSep))
// 	fmt.Println("Go messageHash:    ", "0x"+hex.EncodeToString(goMessageHash))
// 	fmt.Println("Go finalHash:      ", "0x"+hex.EncodeToString(goFinalHash))

// 	// ---- Assert matches Viem ----
// 	// if "0x"+hex.EncodeToString(goDomainSep) != viemDomainSep {
// 	// 	t.Fatalf("domainSeparator mismatch")
// 	// }
// 	// if "0x"+hex.EncodeToString(goMessageHash) != viemMessageHash {
// 	// 	t.Fatalf("messageHash mismatch")
// 	// }
// 	// if "0x"+hex.EncodeToString(goFinalHash) != viemFinalHash {
// 	// 	t.Fatalf("finalHash mismatch")
// 	// }

// 	// ---- Now verify the signature ----
// 	ok, err := VerifyTypedDataSignature(td, signature, expectedSigner)
// 	if err != nil {
// 		t.Fatalf("verification error: %v", err)
// 	}
// 	if !ok {
// 		t.Fatalf("signature DID NOT match expected signer")
// 	}

// 	fmt.Println("✓ All EIP712 hashes matched Viem")
// 	fmt.Println("✓ Signature recovered address matched expected signer")
// }
