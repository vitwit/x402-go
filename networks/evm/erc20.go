package evm

import (
	"context"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

const erc20ABI = `[
	{"constant":true,"inputs":[{"name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"type":"function"},
	{"constant":true,"inputs":[{"name":"owner","type":"address"},{"name":"spender","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"type":"function"},
	{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"}
]`

// ERC20Caller makes read-only calls to any ERC-20 token contract.
type ERC20Caller struct {
	address common.Address
	abi     abi.ABI
	client  *ethclient.Client
}

func newERC20Caller(tokenAddr string, client *ethclient.Client) (*ERC20Caller, error) {
	parsed, err := abi.JSON(strings.NewReader(erc20ABI))
	if err != nil {
		return nil, err
	}
	return &ERC20Caller{
		address: common.HexToAddress(tokenAddr),
		abi:     parsed,
		client:  client,
	}, nil
}

func (e *ERC20Caller) call(ctx context.Context, method string, args ...interface{}) ([]byte, error) {
	data, err := e.abi.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	return e.client.CallContract(ctx, ethereum.CallMsg{To: &e.address, Data: data}, nil)
}

// BalanceOf returns the token balance of owner in atomic units.
func (e *ERC20Caller) BalanceOf(ctx context.Context, owner common.Address) (*big.Int, error) {
	out, err := e.call(ctx, "balanceOf", owner)
	if err != nil {
		return nil, err
	}
	var balance *big.Int
	if err := e.abi.UnpackIntoInterface(&balance, "balanceOf", out); err != nil {
		return nil, err
	}
	return balance, nil
}

// Allowance returns how many tokens owner has approved spender to spend.
func (e *ERC20Caller) Allowance(ctx context.Context, owner, spender common.Address) (*big.Int, error) {
	out, err := e.call(ctx, "allowance", owner, spender)
	if err != nil {
		return nil, err
	}
	var amount *big.Int
	if err := e.abi.UnpackIntoInterface(&amount, "allowance", out); err != nil {
		return nil, err
	}
	return amount, nil
}

// Decimals returns the token's decimal places.
func (e *ERC20Caller) Decimals(ctx context.Context) (uint8, error) {
	out, err := e.call(ctx, "decimals")
	if err != nil {
		return 0, err
	}
	results := make([]interface{}, 1)
	if err := e.abi.UnpackIntoInterface(&results, "decimals", out); err != nil {
		return 0, err
	}
	return results[0].(uint8), nil
}
