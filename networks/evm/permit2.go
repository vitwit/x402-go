package evm

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/vitwit/x402-go"
)

var (
	// permit2Address is the canonical Uniswap Permit2 contract, deployed at the same
	// address on every EVM chain.
	permit2Address = common.HexToAddress("0x000000000022D473030F116dDEE9F6B43aC78BA3")

	// permit2ProxyAddress is the canonical x402ExactPermit2Proxy contract.
	permit2ProxyAddress = common.HexToAddress("0x402085c248EeA27D92E8b30b2C58ed07f9E20001")
)

// Permit2 EIP-712 type hashes.
var (
	permit2DomainTypeHash = crypto.Keccak256Hash(
		[]byte("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
	)
	tokenPermissionsTypeHash = crypto.Keccak256Hash(
		[]byte("TokenPermissions(address token,uint256 amount)"),
	)
	paymentWitnessTypeHash = crypto.Keccak256Hash(
		[]byte("PaymentWitness(address to,uint256 validAfter)"),
	)
	// Full type string: main type + all sub-types in alphabetical order.
	permit2WitnessTypeHash = crypto.Keccak256Hash([]byte(
		"PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,PaymentWitness witness)" +
			"PaymentWitness(address to,uint256 validAfter)" +
			"TokenPermissions(address token,uint256 amount)",
	))
)

// permit2DomainSeparator computes the EIP-712 domain separator for the Permit2 contract.
func permit2DomainSeparator(chainID int64) common.Hash {
	uint256T, _ := abi.NewType("uint256", "", nil)
	addressT, _ := abi.NewType("address", "", nil)
	bytes32T, _ := abi.NewType("bytes32", "", nil)

	args := abi.Arguments{{Type: bytes32T}, {Type: bytes32T}, {Type: uint256T}, {Type: addressT}}
	packed, err := args.Pack(
		permit2DomainTypeHash,
		crypto.Keccak256Hash([]byte("Permit2")),
		big.NewInt(chainID),
		permit2Address,
	)
	if err != nil {
		panic(fmt.Sprintf("permit2DomainSeparator pack: %v", err))
	}
	return crypto.Keccak256Hash(packed)
}

// permit2StructHash computes the EIP-712 struct hash for a Permit2 x402 payment.
func permit2StructHash(auth *x402.Permit2Authorization) (common.Hash, error) {
	uint256T, _ := abi.NewType("uint256", "", nil)
	addressT, _ := abi.NewType("address", "", nil)
	bytes32T, _ := abi.NewType("bytes32", "", nil)

	tokenAmount, ok := new(big.Int).SetString(auth.Permitted.Amount, 10)
	if !ok {
		return common.Hash{}, fmt.Errorf("invalid permitted.amount: %s", auth.Permitted.Amount)
	}
	tokenArgs := abi.Arguments{{Type: bytes32T}, {Type: addressT}, {Type: uint256T}}
	tokenPacked, err := tokenArgs.Pack(tokenPermissionsTypeHash, common.HexToAddress(auth.Permitted.Token), tokenAmount)
	if err != nil {
		return common.Hash{}, fmt.Errorf("pack token permissions: %w", err)
	}
	tokenHash := crypto.Keccak256Hash(tokenPacked)

	validAfter, err := strconv.ParseInt(auth.Witness.ValidAfter, 10, 64)
	if err != nil {
		return common.Hash{}, fmt.Errorf("invalid witness.validAfter: %w", err)
	}
	witnessArgs := abi.Arguments{{Type: bytes32T}, {Type: addressT}, {Type: uint256T}}
	witnessPacked, err := witnessArgs.Pack(paymentWitnessTypeHash, common.HexToAddress(auth.Witness.To), big.NewInt(validAfter))
	if err != nil {
		return common.Hash{}, fmt.Errorf("pack witness: %w", err)
	}
	witnessHash := crypto.Keccak256Hash(witnessPacked)

	nonce, ok := new(big.Int).SetString(auth.Nonce, 10)
	if !ok {
		return common.Hash{}, fmt.Errorf("invalid nonce: %s", auth.Nonce)
	}
	deadline, err := strconv.ParseInt(auth.Deadline, 10, 64)
	if err != nil {
		return common.Hash{}, fmt.Errorf("invalid deadline: %w", err)
	}

	structArgs := abi.Arguments{
		{Type: bytes32T}, // typeHash
		{Type: bytes32T}, // tokenPermissionsHash
		{Type: addressT}, // spender
		{Type: uint256T}, // nonce
		{Type: uint256T}, // deadline
		{Type: bytes32T}, // witnessHash
	}
	structPacked, err := structArgs.Pack(
		permit2WitnessTypeHash,
		tokenHash,
		common.HexToAddress(auth.Spender),
		nonce,
		big.NewInt(deadline),
		witnessHash,
	)
	if err != nil {
		return common.Hash{}, fmt.Errorf("pack struct: %w", err)
	}
	return crypto.Keccak256Hash(structPacked), nil
}

// verifyPermit2 verifies a Permit2 permitWitnessTransferFrom payment.
func (v *Verifier) verifyPermit2(ctx context.Context, req x402.VerifyRequest, payload x402.EVMPayload) (x402.VerifyResult, error) {
	auth := payload.Permit2Authorization
	if auth == nil {
		return x402.VerifyResult{Error: "missing permit2Authorization"}, nil
	}

	now := time.Now().Unix()

	deadline, err := strconv.ParseInt(auth.Deadline, 10, 64)
	if err != nil || deadline < now+6 {
		return x402.VerifyResult{Error: "permit2_deadline_expired"}, nil
	}

	validAfter, err := strconv.ParseInt(auth.Witness.ValidAfter, 10, 64)
	if err != nil || validAfter > now {
		return x402.VerifyResult{Error: "permit2_not_yet_valid"}, nil
	}

	if !strings.EqualFold(auth.Witness.To, req.PaymentOption.PayTo) {
		return x402.VerifyResult{Error: "permit2_recipient_mismatch"}, nil
	}

	if !strings.EqualFold(auth.Permitted.Token, req.PaymentOption.Asset) {
		return x402.VerifyResult{Error: "permit2_token_mismatch"}, nil
	}

	if !strings.EqualFold(auth.Spender, permit2ProxyAddress.Hex()) {
		return x402.VerifyResult{Error: "permit2_invalid_spender"}, nil
	}

	permittedAmount, ok := new(big.Int).SetString(auth.Permitted.Amount, 10)
	if !ok {
		return x402.VerifyResult{Error: "permit2_invalid_amount"}, nil
	}
	required, ok := new(big.Int).SetString(req.PaymentOption.Amount, 10)
	if !ok {
		return x402.VerifyResult{}, fmt.Errorf("invalid payment option amount")
	}
	switch req.PaymentPayload.Accepted.Scheme {
	case x402.SchemeExact:
		if permittedAmount.Cmp(required) != 0 {
			return x402.VerifyResult{Error: "permit2_insufficient_amount"}, nil
		}
	default: // upto
		if permittedAmount.Cmp(required) < 0 {
			return x402.VerifyResult{Error: "permit2_insufficient_amount"}, nil
		}
	}

	chainID, ok := ChainIDFromNetwork(req.PaymentPayload.Accepted.Network)
	if !ok {
		return x402.VerifyResult{}, fmt.Errorf("unknown network: %s", req.PaymentPayload.Accepted.Network)
	}

	domain := permit2DomainSeparator(chainID)
	structH, err := permit2StructHash(auth)
	if err != nil {
		return x402.VerifyResult{}, fmt.Errorf("compute permit2 struct hash: %w", err)
	}
	digest := hashToSign(domain, structH)

	sig, err := hexToSignature(payload.Signature)
	if err != nil {
		return x402.VerifyResult{}, fmt.Errorf("parse signature: %w", err)
	}
	signer, err := recoverSigner(digest, sig)
	if err != nil {
		return x402.VerifyResult{}, fmt.Errorf("recover signer: %w", err)
	}
	if !strings.EqualFold(signer.Hex(), auth.From) {
		return x402.VerifyResult{Error: "permit2_invalid_signature"}, nil
	}

	if rpcURL := v.rpcEndpoints[req.PaymentPayload.Accepted.Network]; rpcURL != "" {
		owner := common.HexToAddress(auth.From)
		if err := v.checkBalance(ctx, rpcURL, auth.Permitted.Token, owner, required); err != nil {
			return x402.VerifyResult{Error: err.Error()}, nil
		}
		if err := v.checkPermit2Allowance(ctx, rpcURL, auth.Permitted.Token, owner, required); err != nil {
			return x402.VerifyResult{Error: err.Error()}, nil
		}
	}

	return x402.VerifyResult{Valid: true, Payer: signer.Hex()}, nil
}

func (v *Verifier) checkPermit2Allowance(ctx context.Context, rpcURL, tokenAddr string, owner common.Address, required *big.Int) error {
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return fmt.Errorf("dial rpc for allowance check: %w", err)
	}
	defer client.Close()

	caller, err := newERC20Caller(tokenAddr, client)
	if err != nil {
		return fmt.Errorf("create erc20 caller: %w", err)
	}
	allowance, err := caller.Allowance(ctx, owner, permit2Address)
	if err != nil {
		return fmt.Errorf("allowance: %w", err)
	}
	if allowance.Cmp(required) < 0 {
		return fmt.Errorf("insufficient_permit2_allowance")
	}
	return nil
}

// x402ExactPermit2Proxy settle ABI.
// settle(address token, uint256 amount, address from, uint256 nonce, uint256 deadline,
//
//	address to, uint256 validAfter, bytes signature)
const permit2ProxySettleABI = `[{
	"name": "settle",
	"type": "function",
	"stateMutability": "nonpayable",
	"inputs": [
		{"name": "token",      "type": "address"},
		{"name": "amount",     "type": "uint256"},
		{"name": "from",       "type": "address"},
		{"name": "nonce",      "type": "uint256"},
		{"name": "deadline",   "type": "uint256"},
		{"name": "to",         "type": "address"},
		{"name": "validAfter", "type": "uint256"},
		{"name": "signature",  "type": "bytes"}
	],
	"outputs": []
}]`

// settlePermit2 executes a Permit2 payment by calling x402ExactPermit2Proxy.settle.
func settlePermit2(ctx context.Context, cfg SettlerConfig, network string, payload x402.EVMPayload) (x402.SettleResult, error) {
	auth := payload.Permit2Authorization
	if auth == nil {
		return x402.SettleResult{Error: "missing permit2Authorization"}, nil
	}

	rpcURL, ok := cfg.RPCEndpoints[network]
	if !ok {
		return x402.SettleResult{Error: "no RPC endpoint for " + network}, nil
	}

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	privKey, err := loadPrivateKey(cfg.PrivateKeyHex)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("parse private key: %w", err)
	}
	facilitatorAddr := crypto.PubkeyToAddress(privKey.PublicKey)

	parsedABI, err := abi.JSON(strings.NewReader(permit2ProxySettleABI))
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("parse permit2 proxy ABI: %w", err)
	}

	tokenAmount, ok := new(big.Int).SetString(auth.Permitted.Amount, 10)
	if !ok {
		return x402.SettleResult{Error: "invalid permitted amount"}, nil
	}
	nonce, ok := new(big.Int).SetString(auth.Nonce, 10)
	if !ok {
		return x402.SettleResult{Error: "invalid nonce"}, nil
	}
	deadline, err := strconv.ParseInt(auth.Deadline, 10, 64)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("parse deadline: %w", err)
	}
	validAfter, err := strconv.ParseInt(auth.Witness.ValidAfter, 10, 64)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("parse validAfter: %w", err)
	}
	sig, err := hexToSignature(payload.Signature)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("parse signature: %w", err)
	}

	data, err := parsedABI.Pack("settle",
		common.HexToAddress(auth.Permitted.Token),
		tokenAmount,
		common.HexToAddress(auth.From),
		nonce,
		big.NewInt(deadline),
		common.HexToAddress(auth.Witness.To),
		big.NewInt(validAfter),
		sig,
	)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("pack calldata: %w", err)
	}

	chainID, err := client.NetworkID(ctx)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("get network id: %w", err)
	}
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
		To:   &permit2ProxyAddress,
		Data: data,
	})
	if err != nil {
		estimatedGas = 150_000
	}
	gasLimit := estimatedGas * 2
	if gasLimit < 150_000 {
		gasLimit = 150_000
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     txNonce,
		GasTipCap: gasTip,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit,
		To:        &permit2ProxyAddress,
		Data:      data,
	})

	signer := types.NewLondonSigner(chainID)
	signed, err := types.SignTx(tx, signer, privKey)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("sign tx: %w", err)
	}
	if err := client.SendTransaction(ctx, signed); err != nil {
		return x402.SettleResult{Error: err.Error()}, nil
	}

	receipt, err := waitForReceipt(ctx, client, signed)
	if err != nil {
		return x402.SettleResult{Error: err.Error()}, nil
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
