package clients

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/vitwit/x402/types"
	x402types "github.com/vitwit/x402/types"
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

	payloadType, parsed, err := ParseEvmPaymentPayload(data)
	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("invalid evm payload: %w", err)
	}

	fmt.Println(payloadType)
	p := parsed.(types.EIP3009Payload)
	fmt.Println("===========================================================")
	fmt.Println(p.Authorization.From)
	fmt.Println(p.Authorization.Nonce)
	fmt.Println(p.Authorization.To)
	fmt.Println(p.Authorization.ValidBefore)
	fmt.Println(p.Authorization.ValidAfter)
	fmt.Println(p.Authorization.Value)
	fmt.Println(p.Signature)
	fmt.Println("===========================================================")

	// At this point: p := parsed.(types.EIP3009Payload)

	auth := p.Authorization
	reqs := payload.PaymentRequirements // assuming this exists

	chainID, err := e.client.ChainID(ctx)
	if err != nil {
		return nil, err
	}

	// 1. Verify signature → recover signer
	signer, err := RecoverEIP3009Signer(auth, p.Signature, chainID, payload.PaymentRequirements.Asset)
	fmt.Println("============================================")
	fmt.Println(signer)
	fmt.Println(err)
	fmt.Println("Using verifyingContract:", payload.PaymentRequirements.Asset)
	fmt.Println(chainID)
	fmt.Println(strings.EqualFold(signer, auth.From))
	fmt.Println("============================================")
	if err != nil || !strings.EqualFold(signer, auth.From) {
		panic("OOPS")
		return &x402types.VerificationResult{
			InvalidReason: "invalid_max_amount_required",
		}, nil
	}

	// 2. Check client ERC20 balance
	erc20 := e.ERC20(reqs.Asset)
	bal, err := erc20.BalanceOf(ctx, common.HexToAddress(auth.From))
	if err != nil {
		return nil, err
	}

	amount, ok := new(big.Int).SetString(reqs.MaxAmountRequired, 10)
	if !ok {
		return &x402types.VerificationResult{
			InvalidReason: "invalid_max_amount_required1",
		}, nil
	}

	if bal.Cmp(amount) < 0 {
		return &x402types.VerificationResult{
			InvalidReason: "invalid_max_amount_required2",
		}, nil
	}

	authValue, ok := new(big.Int).SetString(auth.Value, 10)
	if !ok {
		return &x402types.VerificationResult{
			InvalidReason: "invalid_max_amount_required3",
		}, nil
	}

	// 3. Verify authorization value ≥ paymentRequired
	if authValue.Cmp(amount) < 0 {
		return &x402types.VerificationResult{
			InvalidReason: "invalid_max_amount_required4",
		}, nil
	}

	// 4. Verify validAfter ≤ now ≤ validBefore
	now := big.NewInt(time.Now().Unix())

	validAfter, ok := new(big.Int).SetString(auth.ValidAfter, 10)
	if !ok {
		return &x402types.VerificationResult{
			InvalidReason: "invalid_max_amount_required5",
		}, nil
	}

	validBefore, ok := new(big.Int).SetString(auth.ValidBefore, 10)
	if !ok {
		return &x402types.VerificationResult{
			InvalidReason: "invalid_max_amount_required6",
		}, nil
	}

	if now.Cmp(validAfter) < 0 || now.Cmp(validBefore) > 0 {
		return &x402types.VerificationResult{
			InvalidReason: "invalid_max_amount_required7",
		}, nil
	}

	nonce, err := HexToBytes32(auth.Nonce)

	// 5. Check nonce unused
	used, err := erc20.AuthorizationState(ctx, common.HexToAddress(auth.From), nonce)
	if err != nil {
		return nil, err
	}
	if used {
		return &x402types.VerificationResult{
			InvalidReason: "invalid_max_amount_required8",
		}, nil
	}

	// 6. Validate token address + chain ID
	// if !strings.EqualFold(reqs.Asset, p.Token) { // or auth.TokenAddress if available
	// 	return x402types.Fail("wrong_token"), nil
	// }
	// if p.ChainID.Cmp(e.chainID) != 0 {
	// 	return x402types.Fail("wrong_chain"), nil
	// }

	v, r, s, err := SplitSignature(p.Signature)
	if err != nil {
		return nil, err
	}

	// 7. Simulate transferWithAuthorization
	ok, err = e.SimulateTransferWithAuthorization(ctx, payload.PaymentRequirements.Asset, auth, v, r, s)
	if err != nil {
		return nil, err
	}
	if !ok {
		fmt.Println(err)
		return &x402types.VerificationResult{
			InvalidReason: "invalid_max_amount_required",
		}, nil
	}

	// All checks successful
	return &x402types.VerificationResult{
		IsValid: true,
	}, nil

}

const usdcABI = `
[
  {
    "name": "transferWithAuthorization",
    "type": "function",
    "stateMutability": "nonpayable",
    "inputs": [
      { "name": "from", "type": "address" },
      { "name": "to", "type": "address" },
      { "name": "value", "type": "uint256" },
      { "name": "validAfter", "type": "uint256" },
      { "name": "validBefore", "type": "uint256" },
      { "name": "nonce", "type": "bytes32" },
      { "name": "v", "type": "uint8" },
      { "name": "r", "type": "bytes32" },
      { "name": "s", "type": "bytes32" }
    ],
    "outputs": []
  }
]
`

func SplitSignature(sigHex string) (v uint8, r [32]byte, s [32]byte, err error) {
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	if err != nil {
		return
	}
	if len(sigBytes) != 65 {
		err = fmt.Errorf("invalid signature length: %d", len(sigBytes))
		return
	}

	copy(r[:], sigBytes[0:32])
	copy(s[:], sigBytes[32:64])
	v = sigBytes[64]

	// Normalize v from 27/28 → 0/1
	if v >= 27 {
		v -= 27
	}
	return
}

func (e *EVMClient) SimulateTransferWithAuthorization(
	ctx context.Context,
	token string,
	auth types.EIP3009Authorization,
	v uint8,
	r [32]byte,
	s [32]byte,
) (bool, error) {

	contract := common.HexToAddress(token)

	// Build call data for transferWithAuthorization()
	abi, err := abi.JSON(strings.NewReader(usdcABI)) // ABI shown below
	if err != nil {
		return false, err
	}

	callData, err := abi.Pack(
		"transferWithAuthorization",
		common.HexToAddress(auth.From),
		common.HexToAddress(auth.To),
		mustBig(auth.Value),
		mustBig(auth.ValidAfter),
		mustBig(auth.ValidBefore),
		mustBytes32(auth.Nonce),
		v,
		r,
		s,
	)
	if err != nil {
		return false, err
	}

	// Do eth_call
	msg := ethereum.CallMsg{
		From: common.HexToAddress(auth.From),
		To:   &contract,
		Data: callData,
	}

	_, err = e.client.CallContract(ctx, msg, nil)
	if err != nil {
		// If revert → simulation failed
		return false, nil
	}

	return true, nil
}

func (e *EVMClient) ERC20(token string) ERC20 {
	erc, _ := newERC20(token, e.client)
	return erc
}

func RecoverEIP3009Signer(auth types.EIP3009Authorization, sigHex string, chainID *big.Int, verifyingContract string) (string, error) {
	// decode signature
	sig, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("bad sig hex: %w", err)
	}
	if len(sig) != 65 {
		return "", fmt.Errorf("sig length=%d", len(sig))
	}

	// convert fields
	valueBI, ok := new(big.Int).SetString(auth.Value, 10)
	if !ok {
		return "", fmt.Errorf("bad value")
	}
	validAfterBI, ok := new(big.Int).SetString(auth.ValidAfter, 10)
	if !ok {
		return "", fmt.Errorf("bad validAfter")
	}
	validBeforeBI, ok := new(big.Int).SetString(auth.ValidBefore, 10)
	if !ok {
		return "", fmt.Errorf("bad validBefore")
	}

	nonceB, err := hex.DecodeString(strings.TrimPrefix(auth.Nonce, "0x"))
	if err != nil {
		return "", fmt.Errorf("bad nonce hex: %w", err)
	}
	if len(nonceB) != 32 {
		return "", fmt.Errorf("nonce length=%d", len(nonceB))
	}
	var nonce32 [32]byte
	copy(nonce32[:], nonceB)

	// build domain separator (USD Coin, version "2")
	domain := crypto.Keccak256(
		[]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
		crypto.Keccak256([]byte("USD Coin")),
		crypto.Keccak256([]byte("2")),
		leftPadBig(chainID, 32),
		leftPadAddress(verifyingContract),
	)

	typeHash := crypto.Keccak256Hash([]byte("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"))

	structHash := crypto.Keccak256(
		typeHash.Bytes(),
		leftPadAddress(auth.From),
		leftPadAddress(auth.To),
		leftPadBig(valueBI, 32),
		leftPadBig(validAfterBI, 32),
		leftPadBig(validBeforeBI, 32),
		nonce32[:],
	)

	digest := crypto.Keccak256(
		[]byte("\x19\x01"),
		domain,
		structHash,
	)

	// helper to attempt recovery with a given v convention
	tryRecover := func(sigBytes []byte) (string, error) {
		pub, err := crypto.SigToPub(digest, sigBytes)
		if err != nil {
			return "", err
		}
		return crypto.PubkeyToAddress(*pub).Hex(), nil
	}

	// try as-is first (common case: v == 27 or 28)
	addr1, err1 := tryRecover(sig)
	// try normalize where v is 0/1 → add 27
	sig2 := make([]byte, 65)
	copy(sig2, sig)
	if sig2[64] == 0 || sig2[64] == 1 {
		sig2[64] += 27
	}
	addr2, err2 := tryRecover(sig2)

	// debug print (remove in prod)
	fmt.Println("[Recovery] digest:", "0x"+hex.EncodeToString(digest))
	fmt.Println("[Recovery] sig-v:", sig[64], "addr1:", addr1, "err1:", err1)
	fmt.Println("[Recovery] try v+27 -> v:", sig2[64], "addr2:", addr2, "err2:", err2)

	// pick the one that worked and is non-empty
	if err1 == nil && addr1 != "" {
		return addr1, nil
	}
	if err2 == nil && addr2 != "" {
		return addr2, nil
	}
	// otherwise return a helpful error with both attempts
	return "", fmt.Errorf("recovery failed (attempts: %v, %v)", err1, err2)
}

func HexToBytes32(hexStr string) ([32]byte, error) {
	var out [32]byte

	b, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("invalid nonce length: %d", len(b))
	}

	copy(out[:], b)
	return out, nil
}

func EIP3009Digest(auth types.EIP3009Authorization, chainID *big.Int, tokenAddress string) ([]byte, error) {
	// Apply EIP-712 domain separator (USDC default)
	domainSeparator := crypto.Keccak256(
		[]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
		crypto.Keccak256([]byte("USD Coin")),
		crypto.Keccak256([]byte("2")),
		leftPadBig(chainID, 32),
		leftPadAddress(tokenAddress),
	)

	// Hash the typed struct
	typeHash := crypto.Keccak256Hash([]byte(
		"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
	))

	// Convert Value
	valueBI, ok := new(big.Int).SetString(auth.Value, 10)
	if !ok {
		return nil, fmt.Errorf("invalid value")
	}

	// Convert ValidAfter
	validAfterBI, ok := new(big.Int).SetString(auth.ValidAfter, 10)
	if !ok {
		return nil, fmt.Errorf("invalid validAfter")
	}

	// Convert ValidBefore
	validBeforeBI, ok := new(big.Int).SetString(auth.ValidBefore, 10)
	if !ok {
		return nil, fmt.Errorf("invalid validBefore")
	}

	// Convert Nonce hex → [32]byte
	nonceBytes, err := hex.DecodeString(strings.TrimPrefix(auth.Nonce, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid nonce hex: %w", err)
	}
	if len(nonceBytes) != 32 {
		return nil, fmt.Errorf("nonce must be 32 bytes")
	}

	var nonce32 [32]byte
	copy(nonce32[:], nonceBytes)

	structHash := crypto.Keccak256(
		typeHash.Bytes(),
		leftPadAddress(auth.From),
		leftPadAddress(auth.To),
		leftPadBig(valueBI, 32),
		leftPadBig(validAfterBI, 32),
		leftPadBig(validBeforeBI, 32),
		nonceBytes, // already bytes32
	)

	// Final EIP-712 digest
	return crypto.Keccak256(
		[]byte("\x19\x01"),
		domainSeparator,
		structHash,
	), nil
}

func leftPadBig(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

func leftPadAddress(addr string) []byte {
	a := common.HexToAddress(addr)
	return append(make([]byte, 12), a.Bytes()...) // 32-byte padded
}

func ParseEvmPaymentPayload(raw []byte) (string, interface{}, error) {

	fmt.Println(string(raw))
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

	fmt.Println("=============================")
	fmt.Println("here")
	fmt.Println("=============================")

	return "", nil, errors.New("unknown evm payment payload type")
}

func mustBig(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

func mustBytes32(hexStr string) [32]byte {
	var out [32]byte
	b, _ := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
	copy(out[:], b)
	return out
}
