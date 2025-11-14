package clients

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/shopspring/decimal"
	"github.com/vitwit/x402/types"
	x402types "github.com/vitwit/x402/types"
	"github.com/vitwit/x402/utils/eip712"
)

var _ Client = (*EVMClient)(nil)

// EVMClient provides basic Ethereum functionality
type EVMClient struct {
	rpcURL   string
	network  x402types.Network
	client   *ethclient.Client
	tokenABI abi.ABI // ERC20 ABI
}

func NewEVMClient(network x402types.Network, rpcURL string) (*EVMClient, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum RPC: %w", err)
	}

	return &EVMClient{
		network: network,
		rpcURL:  rpcURL,
		client:  client,
	}, nil
}

// Close implements Client.
func (e *EVMClient) Close() {
	// panic("unimplemented")
	return

}

// GetNetwork implements Client.
func (e *EVMClient) GetNetwork() types.Network {
	return e.network
}

// SettlePayment implements Client.
func (e *EVMClient) SettlePayment(ctx context.Context, payload *types.VerifyRequest) (*types.SettlementResult, error) {
	// panic("unimplemented")

	return nil, nil
}

// VerifyPayment implements Client.
// VerifyPayment verifies an EVM-style x402 payment (EIP-2612 or EIP-3009).
func (e *EVMClient) VerifyPayment(ctx context.Context, payload *x402types.VerifyRequest) (*x402types.VerificationResult, error) {

	if e.rpcURL == "" {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: "RPC client not initialized",
		}, nil
	}

	data, err := base64.StdEncoding.DecodeString(payload.PaymentPayload.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	var header types.EthereumPermitPayload
	if err := json.Unmarshal([]byte(data), &header); err != nil {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("invalid payment header: %v", err),
		}, nil
	}

	paymentPayload := payload.PaymentPayload
	// 2) basic schema checks
	if paymentPayload.Scheme != "exact" {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "scheme must be 'exact'"}, nil
	}

	if header.Authorization.From == "" || header.Authorization.To == "" || header.Authorization.Value == "" || header.Authorization.Nonce == "" {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "authorization missing required fields"}, nil
	}
	// PaymentRequirements checks
	pr := payload.PaymentRequirements
	if pr.PayTo == "" {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "paymentRequirements.payTo missing"}, nil
	}
	if pr.Asset == "" {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "paymentRequirements.asset missing"}, nil
	}
	if pr.MaxAmountRequired == "" {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "paymentRequirements.maxAmountRequired missing"}, nil
	}

	// 3) ensure recipient matches payTo
	if !strings.EqualFold(header.Authorization.To, pr.PayTo) {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "authorization.to does not match paymentRequirements.payTo"}, nil
	}

	// 4) numeric checks: value <= maxAmountRequired
	valueBI, ok := new(big.Int).SetString(header.Authorization.Value, 10)
	if !ok {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "authorization.value invalid decimal"}, nil
	}
	maxBI, ok := new(big.Int).SetString(pr.MaxAmountRequired, 10)
	if !ok {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "paymentRequirements.maxAmountRequired invalid decimal"}, nil
	}
	if valueBI.Cmp(maxBI) > 0 {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "authorization.value exceeds maxAmountRequired"}, nil
	}

	// 5) time window check (validAfter <= now <= validBefore)
	now := time.Now().Unix()
	if header.Authorization.ValidAfter != 0 {
		va := header.Authorization.ValidAfter
		if now < int64(va) {
			return &x402types.VerificationResult{IsValid: false, InvalidReason: "authorization not yet valid (validAfter)"}, nil
		}
	}

	if header.Authorization.ValidBefore != 0 {
		vb := header.Authorization.ValidBefore
		if now > int64(vb) {
			return &x402types.VerificationResult{IsValid: false, InvalidReason: "authorization expired (validBefore)"}, nil
		}
	}

	// 6) build EIP-712 domain
	chainIDStr := payload.PaymentPayload.Network
	if chainIDStr == "" {
		// fallback to paymentRequirements.network
		chainIDStr = pr.Network
	}
	// if network is a chain-name, map to chain-id string; otherwise assume numeric string is provided
	// if _, ok := new(big.Int).SetString(chainIDStr, 10); !ok {
	// 	if mapped, found := networkToChainID(chainIDStr); found {
	// 		chainIDStr = mapped
	// 	} else {
	// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "unable to determine chainId from paymentPayload.network/paymentRequirements.network"}, nil
	// 	}
	// }

	// domain name/version: try extras, fallback to token address string
	name := ""
	version := ""
	if pr.Extra != nil {
		if n, ok := pr.Extra["name"].(string); ok {
			name = n
		}
		if v, ok := pr.Extra["version"].(string); ok {
			version = v
		}
	}
	if name == "" {
		name = pr.Asset // fallback
	}
	if version == "" {
		version = "1"
	}

	domain := eip712.EIP712Domain{
		Name:              name,
		Version:           version,
		ChainId:           chainIDStr,
		VerifyingContract: pr.Asset,
	}

	// 7) compute EIP-712 digest for EIP-3009 transferWithAuthorization
	digest, err := eip712.BuildTransferWithAuthDigest(
		domain,
		header.Authorization.From,
		header.Authorization.To,
		header.Authorization.Value, // decimal string
		strconv.FormatInt(int64(header.Authorization.ValidAfter), 10),  // decimal string
		strconv.FormatInt(int64(header.Authorization.ValidBefore), 10), // decimal string
		header.Authorization.Nonce,                                     // hex nonce
	)
	if err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("failed building EIP-712 digest: %v", err)}, nil
	}

	// 8) parse and normalize signature
	sigBytes, err := parseSignature(header.Signature)
	if err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("bad signature encoding: %v", err)}, nil
	}
	if len(sigBytes) != 65 {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "signature must be 65 bytes"}, nil
	}
	// normalize v to 0/1
	if sigBytes[64] >= 27 {
		sigBytes[64] -= 27
	}

	// 9) recover signer
	pub, err := crypto.SigToPub(digest.Bytes(), sigBytes)
	if err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("signature recovery failed: %v", err)}, nil
	}
	recovered := crypto.PubkeyToAddress(*pub).Hex()

	// 10) compare recovered address to declared authorization.from (case-insensitive)
	if !strings.EqualFold(recovered, header.Authorization.From) {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "signature does not match authorization.from"}, nil
	}

	// 11) success -> return verification result (confirmations = 0 for off-chain)
	amt := decimal.NewFromBigInt(valueBI, 0)
	return &x402types.VerificationResult{
		IsValid:       true,
		InvalidReason: "",
		Amount:        &amt,
		Token:         pr.Asset,
		Sender:        header.Authorization.From,
		Recipient:     header.Authorization.To,
		Confirmations: 0,
	}, nil
}

// parseSignature accepts "0x..." hex or base64-encoded signature and returns 65-byte r|s|v
func parseSignature(sig string) ([]byte, error) {
	// trim spaces
	sig = strings.TrimSpace(sig)
	if sig == "" {
		return nil, fmt.Errorf("empty signature")
	}
	// hex (0x...) common case
	if strings.HasPrefix(sig, "0x") || (len(sig)%2 == 0 && (strings.ContainsAny(sig, "abcdefABCDEF") || strings.HasPrefix(sig, "0X"))) {
		hexStr := sig
		if strings.HasPrefix(hexStr, "0x") || strings.HasPrefix(hexStr, "0X") {
			hexStr = hexStr[2:]
		}
		b, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, err
		}
		// if signature is r||s||v where v is 27/28 already, keep it — normalization happens upstream
		return b, nil
	}
	// otherwise try base64
	b, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// helper
func decimalPtr(v *big.Int) *decimal.Decimal {
	d := decimal.NewFromBigInt(v, 0)
	return &d
}
