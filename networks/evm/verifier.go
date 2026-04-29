package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/vitwit/x402-go"
)

// TokenDomainConfig holds EIP-712 domain parameters for a token contract.
type TokenDomainConfig struct {
	Name    string
	Version string
}

// DefaultTokenDomains contains known EIP-712 domain configs keyed by lowercase token address.
var DefaultTokenDomains = map[string]TokenDomainConfig{
	strings.ToLower("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"): {Name: "USD Coin", Version: "2"}, // USDC Base mainnet
	strings.ToLower("0x036CbD53842c5426634e7929541eC2318f3dCF7e"): {Name: "USDC", Version: "2"},     // USDC Base Sepolia
	strings.ToLower("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"): {Name: "USD Coin", Version: "2"}, // USDC Ethereum
	strings.ToLower("0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"): {Name: "USD Coin", Version: "2"}, // USDC Polygon
}

// Verifier verifies EVM payment signatures for all supported asset transfer methods.
type Verifier struct {
	networks     []string
	tokenDomains map[string]TokenDomainConfig
	rpcEndpoints map[string]string
}

// NewVerifier creates a Verifier for the given networks.
func NewVerifier(networks []string, tokenDomains map[string]TokenDomainConfig) *Verifier {
	if networks == nil {
		networks = DefaultNetworks()
	}
	if tokenDomains == nil {
		tokenDomains = DefaultTokenDomains
	}
	return &Verifier{
		networks:     networks,
		tokenDomains: tokenDomains,
		rpcEndpoints: make(map[string]string),
	}
}

func (v *Verifier) Networks() []string { return v.networks }
func (v *Verifier) Schemes() []x402.Scheme {
	return []x402.Scheme{x402.SchemeExact, x402.SchemeUpto}
}

func (v *Verifier) Verify(ctx context.Context, req x402.VerifyRequest) (x402.VerifyResult, error) {
	var payload x402.EVMPayload
	if err := json.Unmarshal(req.PaymentPayload.Payload, &payload); err != nil {
		return x402.VerifyResult{}, fmt.Errorf("unmarshal evm payload: %w", err)
	}

	var extra struct {
		AssetTransferMethod string `json:"assetTransferMethod"`
	}
	if len(req.PaymentOption.Extra) > 0 {
		_ = json.Unmarshal(req.PaymentOption.Extra, &extra)
	}

	switch extra.AssetTransferMethod {
	case "", "eip3009":
		return v.verifyEIP3009(ctx, req, payload)
	case "permit2":
		return v.verifyPermit2(ctx, req, payload)
	case "erc7710":
		return v.verifyERC7710(ctx, req, payload)
	default:
		return x402.VerifyResult{Error: "unsupported_asset_transfer_method"}, nil
	}
}

func (v *Verifier) verifyEIP3009(ctx context.Context, req x402.VerifyRequest, payload x402.EVMPayload) (x402.VerifyResult, error) {
	if payload.Authorization == nil {
		return x402.VerifyResult{Error: "missing authorization"}, nil
	}
	auth := payload.Authorization
	now := time.Now().Unix()

	validAfter, err := parseTimestamp(auth.ValidAfter)
	if err != nil {
		return x402.VerifyResult{Error: "invalid_exact_evm_payload_authorization_valid_after"}, nil
	}
	validBefore, err := parseTimestamp(auth.ValidBefore)
	if err != nil {
		return x402.VerifyResult{Error: "invalid_exact_evm_payload_authorization_valid_before"}, nil
	}

	if validBefore < now+6 {
		return x402.VerifyResult{Error: "invalid_exact_evm_payload_authorization_valid_before"}, nil
	}
	if validAfter > now {
		return x402.VerifyResult{Error: "invalid_exact_evm_payload_authorization_valid_after"}, nil
	}

	value, ok := new(big.Int).SetString(auth.Value, 10)
	if !ok {
		return x402.VerifyResult{}, fmt.Errorf("invalid value: %s", auth.Value)
	}
	required, ok := new(big.Int).SetString(req.PaymentOption.Amount, 10)
	if !ok {
		return x402.VerifyResult{}, fmt.Errorf("invalid amount: %s", req.PaymentOption.Amount)
	}
	switch req.PaymentPayload.Accepted.Scheme {
	case x402.SchemeExact:
		if value.Cmp(required) != 0 {
			return x402.VerifyResult{Error: "invalid_exact_evm_payload_authorization_value"}, nil
		}
	default: // upto
		if value.Cmp(required) < 0 {
			return x402.VerifyResult{Error: "invalid_exact_evm_payload_authorization_value"}, nil
		}
	}

	if !strings.EqualFold(auth.To, req.PaymentOption.PayTo) {
		return x402.VerifyResult{Error: "invalid_exact_evm_payload_recipient_mismatch"}, nil
	}

	chainID, ok := ChainIDFromNetwork(req.PaymentPayload.Accepted.Network)
	if !ok {
		return x402.VerifyResult{}, fmt.Errorf("unknown network: %s", req.PaymentPayload.Accepted.Network)
	}

	tokenAddr := common.HexToAddress(req.PaymentOption.Asset)
	domainCfg, ok := v.tokenDomains[strings.ToLower(tokenAddr.Hex())]
	if !ok {
		domainCfg = TokenDomainConfig{Name: "Token", Version: "1"}
	}

	domain := domainSeparator(domainCfg.Name, domainCfg.Version, chainID, tokenAddr)
	fromAddr := common.HexToAddress(auth.From)
	toAddr := common.HexToAddress(auth.To)
	nonce, err := hexToBytes32(auth.Nonce)
	if err != nil {
		return x402.VerifyResult{}, fmt.Errorf("parse nonce: %w", err)
	}

	sh := structHash(fromAddr, toAddr, value, validAfter, validBefore, nonce)
	digest := hashToSign(domain, sh)

	sig, err := hexToSignature(payload.Signature)
	if err != nil {
		return x402.VerifyResult{}, fmt.Errorf("parse signature: %w", err)
	}
	signer, err := recoverSigner(digest, sig)
	if err != nil {
		return x402.VerifyResult{}, fmt.Errorf("recover signer: %w", err)
	}
	if !strings.EqualFold(signer.Hex(), auth.From) {
		return x402.VerifyResult{Error: "invalid_exact_evm_payload_signature"}, nil
	}

	if rpcURL := v.rpcEndpoints[req.PaymentPayload.Accepted.Network]; rpcURL != "" {
		if err := v.checkBalance(ctx, rpcURL, req.PaymentOption.Asset, fromAddr, required); err != nil {
			return x402.VerifyResult{Error: err.Error()}, nil
		}
	}

	return x402.VerifyResult{Valid: true, Payer: signer.Hex()}, nil
}

func (v *Verifier) checkBalance(ctx context.Context, rpcURL, tokenAddr string, owner common.Address, required *big.Int) error {
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return fmt.Errorf("dial rpc for balance check: %w", err)
	}
	defer client.Close()

	caller, err := newERC20Caller(tokenAddr, client)
	if err != nil {
		return fmt.Errorf("create erc20 caller: %w", err)
	}
	bal, err := caller.BalanceOf(ctx, owner)
	if err != nil {
		return fmt.Errorf("balanceOf: %w", err)
	}
	if bal.Cmp(required) < 0 {
		return fmt.Errorf("insufficient_funds")
	}
	return nil
}

// parseTimestamp parses a unix timestamp from a JSON string (e.g. "1740672089").
func parseTimestamp(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid timestamp %q: %w", s, err)
	}
	return n, nil
}
