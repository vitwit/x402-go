package clients

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/shopspring/decimal"
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
	panic("unimplemented")
}

// GetNetwork implements Client.
func (e *EVMClient) GetNetwork() types.Network {
	panic("unimplemented")
}

// SettlePayment implements Client.
func (e *EVMClient) SettlePayment(ctx context.Context, payload *types.VerifyRequest) (*types.SettlementResult, error) {
	panic("unimplemented")
}

// VerifyPayment implements Client.
func (c *EVMClient) VerifyPayment(ctx context.Context, payload *x402types.VerifyRequest) (*x402types.VerificationResult, error) {
	// 1️⃣ Decode PaymentHeader (base64 → JSON)
	// txBytes, err := base64.StdEncoding.DecodeString(payload.PaymentHeader)
	// if err != nil {
	// 	return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("invalid base64: %v", err)}, nil
	// }

	// var permit x402types.EthereumPermitPayload
	// if err := json.Unmarshal(txBytes, &permit); err != nil {
	// 	return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("invalid JSON: %v", err)}, nil
	// }

	// // 2️⃣ Basic field sanity checks
	// if permit.Message.Owner == (common.Address{}) || permit.Message.Spender == (common.Address{}) || permit.Token == (common.Address{}) {
	// 	return &x402types.VerificationResult{IsValid: false, InvalidReason: "missing required Ethereum addresses"}, nil
	// }

	// if permit.Message.Value == nil || permit.Message.Value.Sign() <= 0 {
	// 	return &x402types.VerificationResult{IsValid: false, InvalidReason: "invalid or zero value"}, nil
	// }

	// // 3️⃣ Deadline check
	// if permit.Message.Deadline > 0 && time.Now().Unix() > permit.Deadline {
	// 	return &x402types.VerificationResult{IsValid: false, InvalidReason: "permit deadline expired"}, nil
	// }

	// // 4️⃣ Rebuild hash (EIP-712 simplified domain)
	// hash := crypto.Keccak256Hash(
	// 	[]byte(permit.Owner.Hex()),
	// 	[]byte(permit.Spender.Hex()),
	// 	[]byte(permit.Value.String()),
	// 	[]byte(fmt.Sprintf("%d", permit.Nonce)),
	// 	[]byte(fmt.Sprintf("%d", permit.Deadline)),
	// )

	// // 5️⃣ Signature validation
	// sig := permit.Signature
	// if len(sig) != 65 {
	// 	return &x402types.VerificationResult{IsValid: false, InvalidReason: "invalid signature length"}, nil
	// }
	// if sig[64] >= 27 {
	// 	sig[64] -= 27
	// }
	// pubKey, err := crypto.SigToPub(hash.Bytes(), sig)
	// if err != nil {
	// 	return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("signature recovery failed: %v", err)}, nil
	// }
	// recovered := crypto.PubkeyToAddress(*pubKey)
	// if recovered != permit.Owner {
	// 	return &x402types.VerificationResult{IsValid: false, InvalidReason: "signature not from owner"}, nil
	// }

	// // 6️⃣ On-chain nonce verification (for ERC20Permit)
	// erc20Abi, err := abi.JSON(strings.NewReader(`[{"constant":true,"inputs":[{"name":"owner","type":"address"}],"name":"nonces","outputs":[{"name":"","type":"uint256"}],"type":"function"}]`))
	// if err != nil {
	// 	return nil, fmt.Errorf("ABI parse failed: %w", err)
	// }

	// callData, err := erc20Abi.Pack("nonces", permit.Owner)
	// if err != nil {
	// 	return nil, fmt.Errorf("ABI pack failed: %w", err)
	// }

	// res, err := c.client.CallContract(ctx, ethereum.CallMsg{
	// 	To:   &permit.Token,
	// 	Data: callData,
	// }, nil)
	// if err != nil {
	// 	return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("on-chain nonce check failed: %v", err)}, nil
	// }

	// var onchainNonce *big.Int
	// if err := erc20Abi.UnpackIntoInterface(&onchainNonce, "nonces", res); err != nil {
	// 	return nil, fmt.Errorf("failed to decode nonce: %w", err)
	// }

	// if permit.Nonce < onchainNonce.Uint64() {
	// 	return &x402types.VerificationResult{IsValid: false, InvalidReason: "nonce already used"}, nil
	// }

	// // 7️⃣ Optional allowance check
	// allowanceAbi, _ := abi.JSON(strings.NewReader(`[{"constant":true,"inputs":[{"name":"owner","type":"address"},{"name":"spender","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"type":"function"}]`))
	// data, _ := allowanceAbi.Pack("allowance", permit.Owner, permit.Spender)
	// out, err := c.client.CallContract(ctx, ethereum.CallMsg{To: &permit.Token, Data: data}, nil)
	// if err == nil {
	// 	var allowance *big.Int
	// 	if err := allowanceAbi.UnpackIntoInterface(&allowance, "allowance", out); err == nil {
	// 		if allowance.Cmp(permit.Value) < 0 {
	// 			return &x402types.VerificationResult{IsValid: false, InvalidReason: "insufficient allowance"}, nil
	// 		}
	// 	}
	// }

	// // ✅ Passed all verification layers
	// return &x402types.VerificationResult{IsValid: true, InvalidReason: ""}, nil

	return nil, nil
}

// helper
func decimalPtr(v *big.Int) *decimal.Decimal {
	d := decimal.NewFromBigInt(v, 0)
	return &d
}
