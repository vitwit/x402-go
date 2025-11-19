package clients

import (
	"context"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Minimal ERC20 ABI
const erc20ABI = `
[
	{"constant":true,"inputs":[{"name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"type":"function"},
	{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"},
	{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"type":"function"}
]
`

type ERC20Caller struct {
	Address common.Address
	ABI     abi.ABI
	Client  *ethclient.Client
}

func NewErc20Caller(addr string, client *ethclient.Client) (*ERC20Caller, error) {
	parsed, err := abi.JSON(strings.NewReader(erc20ABI))
	if err != nil {
		return nil, err
	}
	return &ERC20Caller{
		Address: common.HexToAddress(addr),
		ABI:     parsed,
		Client:  client,
	}, nil
}

func (e *ERC20Caller) call(ctx context.Context, method string, args ...interface{}) ([]byte, error) {
	data, err := e.ABI.Pack(method, args...)
	if err != nil {
		return nil, err
	}

	// IMPORTANT: CallContract returns (result []byte, error)
	return e.Client.CallContract(
		ctx,
		ethereum.CallMsg{
			To:   &e.Address,
			Data: data,
		},
		nil,
	)
}

func (e *ERC20Caller) BalanceOf(ctx context.Context, owner common.Address) (*big.Int, error) {
	out, err := e.call(ctx, "balanceOf", owner)
	if err != nil {
		return nil, err
	}

	var balance *big.Int
	if err := e.ABI.UnpackIntoInterface(&balance, "balanceOf", out); err != nil {
		return nil, err
	}

	return balance, nil
}

func (e *ERC20Caller) Decimals(ctx context.Context) (uint8, error) {
	out, err := e.call(ctx, "decimals")
	if err != nil {
		return 0, err
	}

	var results []interface{}
	err = e.ABI.UnpackIntoInterface(&results, "decimals", out)
	if err != nil {
		return 0, err
	}

	return results[0].(uint8), nil
}

func (e *ERC20Caller) TotalSupply(ctx context.Context) (*big.Int, error) {
	out, err := e.call(ctx, "totalSupply")
	if err != nil {
		return nil, err
	}

	var results []interface{}
	err = e.ABI.UnpackIntoInterface(&results, "totalSupply", out)
	if err != nil {
		return nil, err
	}

	return results[0].(*big.Int), nil
}
