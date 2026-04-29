package evm

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/vitwit/x402-go"
)

// transferWithAuthorizationABI accepts the packed `bytes` signature variant,
// which USDC contracts on Base/Ethereum support alongside the v/r/s variant.
const transferWithAuthorizationABI = `[{
	"name": "transferWithAuthorization",
	"type": "function",
	"stateMutability": "nonpayable",
	"inputs": [
		{"name": "from",        "type": "address"},
		{"name": "to",          "type": "address"},
		{"name": "value",       "type": "uint256"},
		{"name": "validAfter",  "type": "uint256"},
		{"name": "validBefore", "type": "uint256"},
		{"name": "nonce",       "type": "bytes32"},
		{"name": "signature",   "type": "bytes"}
	],
	"outputs": []
}]`

// SettlerConfig holds credentials and RPC endpoints.
type SettlerConfig struct {
	PrivateKeyHex string
	RPCEndpoints  map[string]string
}

// Settler submits EVM payments for all supported asset transfer methods.
type Settler struct {
	networks  []string
	cfg       SettlerConfig
	parsedABI abi.ABI
}

func NewSettler(networks []string, cfg SettlerConfig) (*Settler, error) {
	if networks == nil {
		networks = DefaultNetworks()
	}
	parsed, err := abi.JSON(strings.NewReader(transferWithAuthorizationABI))
	if err != nil {
		return nil, fmt.Errorf("parse abi: %w", err)
	}
	return &Settler{networks: networks, cfg: cfg, parsedABI: parsed}, nil
}

func (s *Settler) Networks() []string { return s.networks }
func (s *Settler) Schemes() []x402.Scheme {
	return []x402.Scheme{x402.SchemeExact, x402.SchemeUpto}
}

func (s *Settler) Settle(ctx context.Context, req x402.SettleRequest) (x402.SettleResult, error) {
	var payload x402.EVMPayload
	if err := json.Unmarshal(req.PaymentPayload.Payload, &payload); err != nil {
		return x402.SettleResult{}, fmt.Errorf("unmarshal evm payload: %w", err)
	}

	var extra struct {
		AssetTransferMethod string `json:"assetTransferMethod"`
	}
	if len(req.PaymentOption.Extra) > 0 {
		_ = json.Unmarshal(req.PaymentOption.Extra, &extra)
	}

	network := req.PaymentPayload.Accepted.Network
	switch extra.AssetTransferMethod {
	case "", "eip3009":
		return s.settleEIP3009(ctx, network, req.PaymentOption.Asset, payload)
	case "permit2":
		return settlePermit2(ctx, s.cfg, network, payload)
	case "erc7710":
		return settleERC7710(ctx, s.cfg, network, payload, req.PaymentOption)
	default:
		return x402.SettleResult{Error: "unsupported_asset_transfer_method"}, nil
	}
}

func (s *Settler) settleEIP3009(ctx context.Context, network, tokenAsset string, payload x402.EVMPayload) (x402.SettleResult, error) {
	if payload.Authorization == nil {
		return x402.SettleResult{Error: "missing authorization"}, nil
	}
	auth := payload.Authorization

	rpcURL, ok := s.cfg.RPCEndpoints[network]
	if !ok {
		return x402.SettleResult{Error: "no RPC endpoint for " + network}, nil
	}

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	privKey, err := loadPrivateKey(s.cfg.PrivateKeyHex)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("parse private key: %w", err)
	}
	facilitatorAddr := crypto.PubkeyToAddress(privKey.PublicKey)

	value, _ := new(big.Int).SetString(auth.Value, 10)
	nonce32, err := hexToBytes32(auth.Nonce)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("parse nonce: %w", err)
	}
	sigBytes, err := hexToSignature(payload.Signature)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("parse signature: %w", err)
	}
	validAfter, err := strconv.ParseInt(auth.ValidAfter, 10, 64)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("parse validAfter: %w", err)
	}
	validBefore, err := strconv.ParseInt(auth.ValidBefore, 10, 64)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("parse validBefore: %w", err)
	}

	data, err := s.parsedABI.Pack(
		"transferWithAuthorization",
		common.HexToAddress(auth.From),
		common.HexToAddress(auth.To),
		value,
		big.NewInt(validAfter),
		big.NewInt(validBefore),
		nonce32,
		sigBytes,
	)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("pack calldata: %w", err)
	}

	chainID, err := client.NetworkID(ctx)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("get network id: %w", err)
	}
	tokenAddr := common.HexToAddress(tokenAsset)

	txNonce, err := client.PendingNonceAt(ctx, facilitatorAddr)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("get nonce: %w", err)
	}
	gasTip, err := client.SuggestGasTipCap(ctx)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("suggest gas tip: %w", err)
	}
	gasFeeCap, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("suggest gas price: %w", err)
	}

	estimatedGas, err := client.EstimateGas(ctx, ethereum.CallMsg{
		From: facilitatorAddr,
		To:   &tokenAddr,
		Data: data,
	})
	if err != nil {
		estimatedGas = 100_000
	}
	gasLimit := estimatedGas * 2
	if gasLimit < 120_000 {
		gasLimit = 120_000
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     txNonce,
		GasTipCap: gasTip,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit,
		To:        &tokenAddr,
		Value:     big.NewInt(0),
		Data:      data,
	})

	londonSigner := types.NewLondonSigner(chainID)
	signed, err := types.SignTx(tx, londonSigner, privKey)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("sign tx: %w", err)
	}
	if err := client.SendTransaction(ctx, signed); err != nil {
		return x402.SettleResult{Error: err.Error()}, nil
	}

	receipt, err := waitForReceipt(ctx, client, signed)
	if err != nil {
		return x402.SettleResult{Error: fmt.Sprintf("wait receipt: %v", err)}, nil
	}
	if receipt.Status == 0 {
		return x402.SettleResult{Error: "transaction reverted"}, nil
	}
	return x402.SettleResult{
		Success:         true,
		TransactionHash: receipt.TxHash.Hex(),
		Network:         network,
		Payer:           auth.From,
	}, nil
}

// loadPrivateKey parses a 0x-prefixed or raw hex private key.
func loadPrivateKey(hex string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(strings.TrimPrefix(hex, "0x"))
}

// waitForReceipt waits for a transaction to be mined and returns its receipt.
func waitForReceipt(ctx context.Context, client *ethclient.Client, tx *types.Transaction) (*types.Receipt, error) {
	return bind.WaitMined(ctx, client, tx)
}
