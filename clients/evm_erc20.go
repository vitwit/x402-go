package clients

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type ERC20 interface {
	BalanceOf(ctx context.Context, owner common.Address) (*big.Int, error)
	AuthorizationState(ctx context.Context, authorizer common.Address, nonce [32]byte) (bool, error)
}

type erc20Wrapper struct {
	caller *Erc20
}

func newERC20(token string, client *ethclient.Client) (*erc20Wrapper, error) {
	c, err := NewErc20(common.HexToAddress(token), client)
	if err != nil {
		return nil, err
	}
	return &erc20Wrapper{caller: c}, nil
}

func (e *erc20Wrapper) BalanceOf(ctx context.Context, owner common.Address) (*big.Int, error) {
	return e.caller.BalanceOf(&bind.CallOpts{Context: ctx}, owner)
}

func (e *erc20Wrapper) AuthorizationState(
	ctx context.Context, authorizer common.Address, nonce [32]byte,
) (bool, error) {
	return e.caller.AuthorizationState(&bind.CallOpts{Context: ctx}, authorizer, nonce)
}
