package clients

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	goethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/vitwit/x402/types"
	x402types "github.com/vitwit/x402/types"
)

const usdcABI = `
[
  {
    "name": "transferWithAuthorization",
    "type": "function",
    "stateMutability": "nonpayable",
    "inputs": [
      { "name": "from",        "type": "address" },
      { "name": "to",          "type": "address" },
      { "name": "value",       "type": "uint256" },
      { "name": "validAfter",  "type": "uint256" },
      { "name": "validBefore", "type": "uint256" },
      { "name": "nonce",       "type": "bytes32" },
      { "name": "signature",   "type": "bytes" }
    ],
    "outputs": []
  }
]

`

var _ Client = (*EVMClient)(nil)

// EVMClient provides basic Ethereum functionality
type EVMClient struct {
	rpcURL     string
	network    x402types.Network
	client     *ethclient.Client
	privateKey *ecdsa.PrivateKey
}

func NewEVMClient(network x402types.Network, rpcURL string, privKeyHex string) (*EVMClient, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum RPC: %w", err)
	}

	pk, err := crypto.HexToECDSA(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid facilitator private key: %w", err)
	}

	return &EVMClient{
		network:    network,
		rpcURL:     rpcURL,
		client:     client,
		privateKey: pk,
	}, nil
}

// Close implements Client.
func (e *EVMClient) Close() {
	e.client.Close()

}

// GetNetwork implements Client.
func (e *EVMClient) GetNetwork() types.Network {
	return e.network
}

// SettlePayment implements Client.
func (e *EVMClient) SettlePayment(ctx context.Context, payload *types.VerifyRequest) (*types.SettlementResult, error) {
	// 1) Re-verify the payment first (signature + basic checks + simulation)
	ver, err := e.VerifyPayment(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("verify payment failed: %w", err)
	}
	if !ver.IsValid {
		return &types.SettlementResult{Success: false, Error: ver.InvalidReason,
			Extra: x402types.ExtraData{
				"feePayer": "",
			},
		}, nil
	}

	// 2) Parse the payload to get the EIP-3009 data
	data, err := base64.StdEncoding.DecodeString(payload.PaymentPayload.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 payload: %w", err)
	}
	_, parsed, err := ParseEvmPaymentPayload(data)
	if err != nil {
		return nil, fmt.Errorf("parse evm payload failed: %w", err)
	}
	p := parsed.(types.EIP3009Payload)

	// 3) Ensure facilitator has a private key
	if e.privateKey == nil {
		return nil, fmt.Errorf("facilitator private key not configured")
	}

	//----------------------------------------------------
	// 4. Build USDC calldata for transferWithAuthorization
	//----------------------------------------------------
	parsedABI, err := abi.JSON(strings.NewReader(usdcABI))
	if err != nil {
		return nil, err
	}

	value, err := strconv.Atoi(p.Authorization.Value)
	if err != nil {
		return nil, err
	}

	vb, err := strconv.Atoi(p.Authorization.ValidBefore)
	if err != nil {
		return nil, err
	}

	va, err := strconv.Atoi(p.Authorization.ValidAfter)
	if err != nil {
		return nil, err
	}

	callData, err := parsedABI.Pack(
		"transferWithAuthorization",
		common.HexToAddress(p.Authorization.From),
		common.HexToAddress(p.Authorization.To),
		big.NewInt(int64(value)),
		big.NewInt(int64(va)),
		big.NewInt(int64(vb)),
		common.HexToHash(p.Authorization.Nonce),
		common.FromHex(p.Signature),
	)
	if err != nil {
		return nil, err
	}

	facilitatorAddr := crypto.PubkeyToAddress(e.privateKey.PublicKey)

	//----------------------------------------------------
	// 5. Build and sign transaction
	//----------------------------------------------------
	nonce, err := e.client.PendingNonceAt(ctx, facilitatorAddr)
	if err != nil {
		return nil, err
	}

	msg := ethereum.CallMsg{
		From: facilitatorAddr,
		To:   &common.Address{},
		Data: callData,
	}
	estimatedGas, err := e.client.EstimateGas(ctx, msg)
	if err != nil {
		return nil, err
	}

	gasLimit := estimatedGas * 2
	if gasLimit < 120_000 {
		gasLimit = 120_000
	}

	chainID, err := e.client.NetworkID(ctx)
	if err != nil {
		return nil, err
	}

	gasTip, err := e.client.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, err
	}

	gasFeeCap, err := e.client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, err
	}

	assetAddress := common.HexToAddress(payload.PaymentRequirements.Asset)
	tx := goethtypes.NewTx(&goethtypes.DynamicFeeTx{
		Nonce:     nonce,
		GasTipCap: gasTip,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit,
		To:        &assetAddress,
		Value:     big.NewInt(0),
		Data:      callData,
	})

	signedTx, err := goethtypes.SignTx(tx, goethtypes.NewLondonSigner(chainID), e.privateKey)
	if err != nil {
		return nil, err
	}

	//----------------------------------------------------
	// 6. Broadcast
	//----------------------------------------------------
	err = e.client.SendTransaction(ctx, signedTx)
	if err != nil {
		return nil, err
	}

	receipt, err := bind.WaitMined(ctx, e.client, signedTx)
	if err != nil {
		return nil, err
	}

	return &x402types.SettlementResult{
		Success:   true,
		TxHash:    receipt.TxHash.Hex(),
		NetworkId: chainID.String(),
		Extra: x402types.ExtraData{
			"feePayer": facilitatorAddr.Hex(),
		},
	}, nil
}

var AuthorizationTypes = map[string][]TypeEntry{
	"EIP712Domain": {
		{Name: "name", Type: "string"},
		{Name: "version", Type: "string"},
		{Name: "chainId", Type: "uint256"},
		{Name: "verifyingContract", Type: "address"},
	},
	"TransferWithAuthorization": {
		{Name: "from", Type: "address"},
		{Name: "to", Type: "address"},
		{Name: "value", Type: "uint256"},
		{Name: "validAfter", Type: "uint256"},
		{Name: "validBefore", Type: "uint256"},
		{Name: "nonce", Type: "bytes32"},
	},
}

// VerifyPayment implements Client.
// VerifyPayment verifies an EVM-style x402 payment (EIP-2612 or EIP-3009).
func (e *EVMClient) VerifyPayment(
	ctx context.Context,
	payload *x402types.VerifyRequest,
) (*x402types.VerificationResult, error) {

	if e.rpcURL == "" {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: "RPC client not initialized",
			Extra: x402types.ExtraData{
				"feePayer": "",
			},
		}, nil
	}

	// -------------------------------------------------------------
	// 1. Decode Base64
	// -------------------------------------------------------------
	data, err := base64.StdEncoding.DecodeString(payload.PaymentPayload.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	// -------------------------------------------------------------
	// 2. Parse EIP3009 payload
	// -------------------------------------------------------------

	pt, parsed, err := ParseEvmPaymentPayload(data)
	if err != nil {
		return nil, fmt.Errorf("invalid evm payload: %w", err)
	}
	if pt != "eip3009" {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: "unsupported_scheme",
			Extra: x402types.ExtraData{
				"feePayer": "",
			},
		}, nil
	}

	p := parsed.(types.EIP3009Payload)

	req := payload.PaymentRequirements
	// -------------------------------------------------------------
	// 3. Validate scheme + network
	// -------------------------------------------------------------
	if payload.PaymentPayload.Scheme != "exact" || req.Scheme != "exact" {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: "unsupported_scheme",
			Extra: x402types.ExtraData{
				"feePayer": "",
			},
		}, nil
	}

	// -------------------------------------------------------------
	// 5. Verify EIP-712 signature
	// -------------------------------------------------------------
	name, ok := payload.PaymentRequirements.Extra["name"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid type for field \"name\": expected string but got %T", payload.PaymentRequirements.Extra["name"])

	}
	version, ok := payload.PaymentRequirements.Extra["version"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid type for field \"version\": expected string but got %T", payload.PaymentRequirements.Extra["version"])
	}

	typedData := TypedData{
		Types:       AuthorizationTypes,
		PrimaryType: "TransferWithAuthorization",
		Domain: TypedDataDomain{
			Name:              name,
			Version:           version,
			ChainId:           payload.PaymentRequirements.Network,
			VerifyingContract: payload.PaymentRequirements.Asset,
		},
		Message: map[string]interface{}{
			"from":        p.Authorization.From,
			"to":          p.Authorization.To,
			"value":       p.Authorization.Value,
			"validAfter":  p.Authorization.ValidAfter,
			"validBefore": p.Authorization.ValidBefore,
			"nonce":       p.Authorization.Nonce,
		},
	}

	types := map[string][]TypeEntry{
		"TransferWithAuthorization": {
			{"from", "address"},
			{"to", "address"},
			{"value", "uint256"},
			{"validAfter", "uint256"},
			{"validBefore", "uint256"},
			{"nonce", "bytes32"},
		},
	}

	digest, err := TypedDataHash(typedData.Domain, "TransferWithAuthorization", typedData.Message, types)
	if err != nil {
		return nil, err
	}

	recovered, err := VerifyTypedDataSignature(
		digest,
		p.Signature,
		common.HexToAddress(p.Authorization.From),
	)

	if err != nil || !recovered {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: "invalid_exact_evm_payload_signature",
			Extra: x402types.ExtraData{
				"feePayer": "",
			},
		}, nil
	}

	// -------------------------------------------------------------
	// 6. Recipient matches
	// -------------------------------------------------------------
	if p.Authorization.To != req.PayTo {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: "invalid_exact_evm_payload_recipient_mismatch",
			Extra: x402types.ExtraData{
				"feePayer": "",
			},
		}, nil
	}

	// -------------------------------------------------------------
	// 7. Time validation
	// -------------------------------------------------------------
	now := time.Now().Unix()

	validBefore, err := strconv.Atoi(p.Authorization.ValidBefore)
	validAfter, err := strconv.Atoi(p.Authorization.ValidAfter)

	if int64(validBefore) < now+6 {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: "invalid_exact_evm_payload_authorization_valid_before",
			Extra: x402types.ExtraData{
				"feePayer": "",
			},
		}, nil
	}

	if int64(validAfter) > now {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: "invalid_exact_evm_payload_authorization_valid_after",
			Extra: x402types.ExtraData{
				"feePayer": "",
			},
		}, nil
	}

	// -------------------------------------------------------------
	// 8. Check balance
	// -------------------------------------------------------------

	caller, err := NewErc20Caller(payload.PaymentRequirements.Asset, e.client)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum RPC: %w", err)
	}

	bal, err := caller.BalanceOf(ctx, common.HexToAddress(p.Authorization.From))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	valueBI, ok := new(big.Int).SetString(p.Authorization.Value, 10)
	if !ok {
		return nil, fmt.Errorf("invalid authorization value: %s", p.Authorization.Value)
	}

	requiredBI, ok := new(big.Int).SetString(req.MaxAmountRequired, 10)
	if !ok {
		return nil, fmt.Errorf("invalid maxAmountRequired: %s", req.MaxAmountRequired)
	}

	if bal.Cmp(requiredBI) < 0 {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: "insufficient_funds",
		}, nil
	}

	// -------------------------------------------------------------
	// 9. Check value is sufficient
	// -------------------------------------------------------------
	if valueBI.Cmp(requiredBI) < 0 {
		return &x402types.VerificationResult{
			IsValid:       false,
			InvalidReason: "invalid_exact_evm_payload_authorization_value",
		}, nil
	}

	n := time.Now()
	return &x402types.VerificationResult{
		IsValid:       true,
		Amount:        p.Authorization.Value,
		Token:         req.Asset,
		Recipient:     req.PayTo,
		Sender:        p.Authorization.From,
		Timestamp:     &n,
		Confirmations: 0,
		Payer:         p.Authorization.From,
	}, nil

}

// VerifyTypedDataSignature verifies that `signatureHex` correctly signs `digest`
// and matches `expectedSigner`.
func VerifyTypedDataSignature(digest []byte, signatureHex string, expectedSigner common.Address) (bool, error) {
	sig, err := normalizeSignature(signatureHex)
	if err != nil {
		return false, err
	}

	// normalize v = 0 or 1 for SigToPub
	if sig[64] >= 27 {
		sig[64] -= 27
	}

	pub, err := crypto.SigToPub(digest, sig)
	if err != nil {
		return false, err
	}

	recovered := crypto.PubkeyToAddress(*pub)

	return bytes.Equal(recovered.Bytes(), expectedSigner.Bytes()), nil
}

// normalizeSignature accepts 65-byte standard or 64-byte compact (EIP-2098)
// and returns a proper 65-byte signature r|s|v.
func normalizeSignature(sigHex string) ([]byte, error) {
	s := strings.TrimPrefix(sigHex, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	switch len(b) {

	case 65:
		// Standard r|s|v
		return b, nil

	case 64:
		// EIP-2098 compact form: r(32) | vs(32)
		r := b[:32]
		vs := b[32:64]

		// highest bit of vs[31] = v bit
		v := byte(27)
		if vs[31]&0x80 != 0 {
			v = 28
		}

		// clear highest bit of s
		vs[31] &= 0x7F

		// build full signature
		out := make([]byte, 65)
		copy(out[0:32], r)
		copy(out[32:64], vs)
		out[64] = v

		return out, nil
	}

	return nil, fmt.Errorf("unexpected signature length %d", len(b))
}

func mustABIType(t string) abi.Type {
	parsed, err := abi.NewType(t, "", nil)
	if err != nil {
		panic(err)
	}
	return parsed
}

func ParseEvmPaymentPayload(raw []byte) (string, interface{}, error) {
	// Try EIP-3009
	if bytes.Contains(raw, []byte(`"authorization"`)) &&
		bytes.Contains(raw, []byte(`"signature"`)) {
		var p types.EIP3009Payload
		if err := json.Unmarshal(raw, &p); err == nil {
			return "eip3009", p, nil
		}
	}

	// Try EIP-2612 Permit
	if bytes.Contains(raw, []byte(`"spender"`)) &&
		bytes.Contains(raw, []byte(`"deadline"`)) &&
		bytes.Contains(raw, []byte(`"signature"`)) {
		var p types.EIP2612PermitPayload
		if err := json.Unmarshal(raw, &p); err == nil {
			return "eip2612", p, nil
		}
	}

	// Try Raw tx
	if bytes.Contains(raw, []byte(`"rawTx"`)) {
		var p types.EVMRawTxPayload
		if err := json.Unmarshal(raw, &p); err == nil {
			return "raw", p, nil
		}
	}

	return "", nil, errors.New("unknown evm payment payload type")
}
