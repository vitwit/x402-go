package clients

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/shopspring/decimal"
	x402types "github.com/vitwit/x402/types"
)

type EVMClient struct {
	network       x402types.Network
	rpcURL        string
	eth           *ethclient.Client
	acceptedToken common.Address // ERC-20 token (zero address = native ETH)
}

func NewEVMClient(network x402types.Network, rpcURL string, tokenAddr string) (*EVMClient, error) {
	eth, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("ethereum rpc dial: %w", err)
	}

	var accepted common.Address
	t := strings.TrimSpace(tokenAddr)
	if t != "" && !strings.EqualFold(t, "ETH") {
		if strings.HasPrefix(t, "0x") && len(t) == 42 {
			accepted = common.HexToAddress(t)
		} else if len(t) == 40 {
			accepted = common.HexToAddress("0x" + t)
		} else {
			accepted = common.Address{} // treat non-hex as native ETH
		}
	}

	return &EVMClient{
		network:       network,
		rpcURL:        rpcURL,
		eth:           eth,
		acceptedToken: accepted,
	}, nil
}

// VerifyPayment checks tx validity and amount
func (c *EVMClient) VerifyPayment(
	ctx context.Context,
	payload *x402types.VerifyRequest,
) (*x402types.VerificationResult, error) {

	data, err := base64.StdEncoding.DecodeString(payload.PaymentHeader)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 header: %w", err)
	}

	var header x402types.EthereumPaymentPayload
	if err := json.Unmarshal(data, &header); err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("invalid payload: %v", err)}, nil
	}

	txBytes, err := hex.DecodeString(strings.TrimPrefix(header.Payment.TxHex, "0x"))
	if err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("invalid tx hex: %v", err)}, nil
	}

	var tx types.Transaction
	if err := rlp.DecodeBytes(txBytes, &tx); err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("rlp decode: %v", err)}, nil
	}

	if tx.To() == nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "contract creation not supported"}, nil
	}
	if *tx.To() != common.HexToAddress(payload.PaymentRequirements.PayTo) {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "recipient mismatch"}, nil
	}

	var sentAmt decimal.Decimal
	var token string

	if c.acceptedToken == (common.Address{}) {
		sentAmt = decimal.NewFromBigInt(tx.Value(), 0)
		token = "ETH"
	} else {
		if tx.Data() == nil || len(tx.Data()) == 0 {
			return &x402types.VerificationResult{IsValid: false, InvalidReason: "no data for ERC-20"}, nil
		}
		if !bytes.HasPrefix(tx.Data(), []byte{0xa9, 0x05, 0x9c, 0xbb}) {
			return &x402types.VerificationResult{IsValid: false, InvalidReason: "not a transfer call"}, nil
		}
		to := common.BytesToAddress(tx.Data()[4:36])
		if to != common.HexToAddress(payload.PaymentRequirements.PayTo) {
			return &x402types.VerificationResult{IsValid: false, InvalidReason: "ERC-20 recipient mismatch"}, nil
		}
		amount := new(big.Int).SetBytes(tx.Data()[36:68])
		sentAmt = decimal.NewFromBigInt(amount, 0)
		token = c.acceptedToken.Hex()
	}

	reqAmt, err := decimal.NewFromString(payload.PaymentRequirements.MaxAmountRequired)
	if err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "invalid required amount"}, nil
	}

	scheme := strings.ToLower(payload.PaymentRequirements.Scheme)
	if scheme == "exact" {
		if !sentAmt.Equal(reqAmt) {
			return &x402types.VerificationResult{IsValid: false, InvalidReason: "payment amount does not equal required amount"}, nil
		}
	} else {
		if sentAmt.LessThan(reqAmt) {
			return &x402types.VerificationResult{IsValid: false, InvalidReason: "insufficient payment"}, nil
		}
	}

	chainID := tx.ChainId()
	if chainID == nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: "missing chain ID in tx"}, nil
	}

	signer := types.LatestSignerForChainID(chainID)
	from, err := types.Sender(signer, &tx)
	if err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("cannot recover sender: %v", err)}, nil
	}

	msg := ethereum.CallMsg{
		From:     from,
		To:       tx.To(),
		Gas:      tx.Gas(),
		GasPrice: tx.GasPrice(),
		Value:    tx.Value(),
		Data:     tx.Data(),
	}

	_, err = c.eth.CallContract(ctx, msg, nil)
	if err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("simulation failed: %v", err)}, nil
	}

	return &x402types.VerificationResult{
		IsValid:       true,
		Amount:        &sentAmt,
		Token:         token,
		Recipient:     payload.PaymentRequirements.PayTo,
		Sender:        from.Hex(),
		Confirmations: 1,
	}, nil
}

func (c *EVMClient) SettlePayment(
	ctx context.Context,
	payload *x402types.VerifyRequest,
) (*x402types.SettlementResult, error) {

	if _, err := c.VerifyPayment(ctx, payload); err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(payload.PaymentHeader)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	var header x402types.EthereumPaymentPayload
	if err := json.Unmarshal(data, &header); err != nil {
		return &x402types.SettlementResult{Success: false, Error: err.Error()}, nil
	}

	txBytes, _ := hex.DecodeString(strings.TrimPrefix(header.Payment.TxHex, "0x"))
	var tx types.Transaction
	if err := rlp.DecodeBytes(txBytes, &tx); err != nil {
		return &x402types.SettlementResult{Success: false, Error: fmt.Sprintf("rlp decode: %v", err)}, nil
	}

	if err := c.eth.SendTransaction(ctx, &tx); err != nil {
		return &x402types.SettlementResult{Success: false, Error: fmt.Sprintf("broadcast failed: %v", err)}, nil
	}
	return &x402types.SettlementResult{
		Success: true,
		TxHash:  tx.Hash().Hex(),
	}, nil
}

func (c *EVMClient) GetNetwork() x402types.Network { return c.network }
func (c *EVMClient) Close()                        { c.eth.Close() }

func (c *EVMClient) WaitForConfirmation(ctx context.Context, txHash string, confirmations int) (*x402types.SettlementResult, error) {
	return &x402types.SettlementResult{
		Success: true,
		TxHash:  txHash,
	}, nil
}
