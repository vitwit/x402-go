package evm

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/vitwit/x402-go"
)

// ERC-7579 / ERC-7710 constants.
var (
	// erc7579SingleCallMode is the execution mode for a single call: all-zero bytes32.
	// CallType=0x00 (single), ExecType=0x00 (default), ModeSelector=0x00000000, ModePayload=0.
	erc7579SingleCallMode = [32]byte{}
)

// EIP-712 type string suffix appended by the delegation framework for the full Permit2 type.
// redeemDelegations ABI.
const redeemDelegationsABI = `[{
	"name": "redeemDelegations",
	"type": "function",
	"stateMutability": "nonpayable",
	"inputs": [
		{"name": "_permissionContexts", "type": "bytes[]"},
		{"name": "_modes",              "type": "bytes32[]"},
		{"name": "_executionCallDatas", "type": "bytes[]"}
	],
	"outputs": []
}]`

// erc20TransferABI is used to encode an ERC-20 transfer call.
const erc20TransferABI = `[{
	"name": "transfer",
	"type": "function",
	"stateMutability": "nonpayable",
	"inputs": [
		{"name": "to",     "type": "address"},
		{"name": "amount", "type": "uint256"}
	],
	"outputs": [{"name": "", "type": "bool"}]
}]`

// buildERC7710ExecutionCallData constructs the ERC-7579 single-execution calldata for
// an ERC-20 transfer(to, amount) call on tokenAddr.
func buildERC7710ExecutionCallData(tokenAddr, payTo common.Address, amount *big.Int) ([]byte, error) {
	transferParsed, err := abi.JSON(strings.NewReader(erc20TransferABI))
	if err != nil {
		return nil, fmt.Errorf("parse transfer abi: %w", err)
	}
	transferCalldata, err := transferParsed.Pack("transfer", payTo, amount)
	if err != nil {
		return nil, fmt.Errorf("pack transfer: %w", err)
	}

	// ERC-7579 single execution encoding: abi.encode(address target, uint256 value, bytes callData)
	addressT, _ := abi.NewType("address", "", nil)
	uint256T, _ := abi.NewType("uint256", "", nil)
	bytesT, _ := abi.NewType("bytes", "", nil)

	execArgs := abi.Arguments{{Type: addressT}, {Type: uint256T}, {Type: bytesT}}
	return execArgs.Pack(tokenAddr, big.NewInt(0), transferCalldata)
}

// verifyERC7710 verifies an ERC-7710 delegated payment via eth_call simulation.
func (v *Verifier) verifyERC7710(ctx context.Context, req x402.VerifyRequest, payload x402.EVMPayload) (x402.VerifyResult, error) {
	if payload.DelegationManager == "" || payload.PermissionContext == "" || payload.Delegator == "" {
		return x402.VerifyResult{Error: "erc7710_missing_fields"}, nil
	}

	rpcURL := v.rpcEndpoints[req.PaymentPayload.Accepted.Network]
	if rpcURL == "" {
		return x402.VerifyResult{Error: "erc7710_no_rpc_for_simulation"}, nil
	}

	amount, ok := new(big.Int).SetString(req.PaymentOption.Amount, 10)
	if !ok {
		return x402.VerifyResult{}, fmt.Errorf("invalid amount: %s", req.PaymentOption.Amount)
	}
	payTo := common.HexToAddress(req.PaymentOption.PayTo)
	token := common.HexToAddress(req.PaymentOption.Asset)

	execData, err := buildERC7710ExecutionCallData(token, payTo, amount)
	if err != nil {
		return x402.VerifyResult{}, fmt.Errorf("build execution calldata: %w", err)
	}

	permCtxBytes, err := hexDecode(payload.PermissionContext)
	if err != nil {
		return x402.VerifyResult{Error: "erc7710_invalid_permission_context"}, nil
	}

	if err := simulateRedeemDelegations(ctx, rpcURL, payload.DelegationManager, permCtxBytes, execData); err != nil {
		return x402.VerifyResult{Error: fmt.Sprintf("erc7710_simulation_failed: %v", err)}, nil
	}

	return x402.VerifyResult{Valid: true, Payer: payload.Delegator}, nil
}

// simulateRedeemDelegations calls redeemDelegations via eth_call to verify the delegation.
func simulateRedeemDelegations(ctx context.Context, rpcURL, delegationManager string, permCtx, execData []byte) error {
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	parsedABI, err := abi.JSON(strings.NewReader(redeemDelegationsABI))
	if err != nil {
		return fmt.Errorf("parse abi: %w", err)
	}

	mode := erc7579SingleCallMode
	data, err := parsedABI.Pack("redeemDelegations",
		[][]byte{permCtx},
		[][32]byte{mode},
		[][]byte{execData},
	)
	if err != nil {
		return fmt.Errorf("pack calldata: %w", err)
	}

	mgr := common.HexToAddress(delegationManager)
	_, err = client.CallContract(ctx, ethereum.CallMsg{To: &mgr, Data: data}, nil)
	return err
}

// settleERC7710 executes an ERC-7710 delegated payment by broadcasting redeemDelegations.
func settleERC7710(ctx context.Context, cfg SettlerConfig, network string, payload x402.EVMPayload, opt x402.PaymentOption) (x402.SettleResult, error) {
	if payload.DelegationManager == "" || payload.PermissionContext == "" || payload.Delegator == "" {
		return x402.SettleResult{Error: "erc7710_missing_fields"}, nil
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

	amount, ok := new(big.Int).SetString(opt.Amount, 10)
	if !ok {
		return x402.SettleResult{Error: "invalid amount"}, nil
	}
	token := common.HexToAddress(opt.Asset)
	payTo := common.HexToAddress(opt.PayTo)

	execData, err := buildERC7710ExecutionCallData(token, payTo, amount)
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("build execution calldata: %w", err)
	}

	permCtxBytes, err := hexDecode(payload.PermissionContext)
	if err != nil {
		return x402.SettleResult{Error: "erc7710_invalid_permission_context"}, nil
	}

	parsedABI, err := abi.JSON(strings.NewReader(redeemDelegationsABI))
	if err != nil {
		return x402.SettleResult{}, fmt.Errorf("parse abi: %w", err)
	}

	mode := erc7579SingleCallMode
	data, err := parsedABI.Pack("redeemDelegations",
		[][]byte{permCtxBytes},
		[][32]byte{mode},
		[][]byte{execData},
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

	mgr := common.HexToAddress(payload.DelegationManager)
	estimatedGas, err := client.EstimateGas(ctx, ethereum.CallMsg{
		From: facilitatorAddr,
		To:   &mgr,
		Data: data,
	})
	if err != nil {
		estimatedGas = 200_000
	}
	gasLimit := estimatedGas * 2
	if gasLimit < 200_000 {
		gasLimit = 200_000
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     txNonce,
		GasTipCap: gasTip,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit,
		To:        &mgr,
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
		return x402.SettleResult{Error: err.Error()}, nil
	}
	if receipt.Status == 0 {
		return x402.SettleResult{Error: "transaction reverted"}, nil
	}
	return x402.SettleResult{
		Success:         true,
		TransactionHash: receipt.TxHash.Hex(),
		Network:         network,
		Payer:           payload.Delegator,
	}, nil
}

// hexDecode decodes a 0x-prefixed hex string to bytes.
func hexDecode(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s)%2 != 0 {
		s = "0" + s
	}
	b := make([]byte, len(s)/2)
	for i := range b {
		_, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &b[i])
		if err != nil {
			return nil, fmt.Errorf("hex decode at position %d: %w", i, err)
		}
	}
	return b, nil
}
