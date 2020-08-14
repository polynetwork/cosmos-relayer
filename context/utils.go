/*
 * Copyright (C) 2020 The poly network Authors
 * This file is part of The poly network library.
 *
 * The  poly network  is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The  poly network  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License
 * along with The poly network .  If not, see <http://www.gnu.org/licenses/>.
 */

package context

import (
	"errors"
	"fmt"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mintkey"
	"github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/cosmos/cosmos-sdk/x/bank"
	"github.com/polynetwork/cosmos-poly-module/btcx"
	"github.com/polynetwork/cosmos-poly-module/ccm"
	"github.com/polynetwork/cosmos-poly-module/ft"
	"github.com/polynetwork/cosmos-poly-module/headersync"
	"github.com/polynetwork/cosmos-poly-module/lockproxy"
	"github.com/polynetwork/cosmos-relayer/log"
	"github.com/polynetwork/poly-go-sdk"
	crypto2 "github.com/tendermint/tendermint/crypto"
	"io/ioutil"
)

func GetAccountByPassword(sdk *poly_go_sdk.PolySdk, path string, pwd []byte) (*poly_go_sdk.Account, error) {
	wallet, err := sdk.OpenWallet(path)
	if err != nil {
		return nil, fmt.Errorf("open wallet error: %v", err)
	}
	user, err := wallet.GetDefaultAccount(pwd)
	if err != nil {
		return nil, fmt.Errorf("getDefaultAccount error: %v", err)
	}
	return user, nil
}

func GetCosmosPrivateKey(path string, pwd []byte) (crypto2.PrivKey, types.AccAddress, error) {
	bz, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, types.AccAddress{}, err
	}

	privKey, _, err := mintkey.UnarmorDecryptPrivKey(string(bz), string(pwd))
	if err != nil {
		return nil, types.AccAddress{}, fmt.Errorf("failed to decrypt private key: v", err)
	}

	return privKey, types.AccAddress(privKey.PubKey().Address().Bytes()), nil
}

func CalcCosmosFees(gasPrice types.DecCoins, gas uint64) (types.Coins, error) {
	if gasPrice.IsZero() {
		return types.Coins{}, errors.New("gas price is zero")
	}
	if gas == 0 {
		return types.Coins{}, errors.New("gas is zero")
	}
	glDec := types.NewDec(int64(gas))
	fees := make(types.Coins, len(gasPrice))
	for i, gp := range gasPrice {
		fee := gp.Amount.Mul(glDec)
		fees[i] = types.NewCoin(gp.Denom, fee.Ceil().RoundInt())
	}
	return fees, nil
}

func NewCodecForRelayer() *codec.Codec {
	cdc := codec.New()
	bank.RegisterCodec(cdc)
	types.RegisterCodec(cdc)
	codec.RegisterCrypto(cdc)
	auth.RegisterCodec(cdc)
	btcx.RegisterCodec(cdc)
	ccm.RegisterCodec(cdc)
	ft.RegisterCodec(cdc)
	headersync.RegisterCodec(cdc)
	lockproxy.RegisterCodec(cdc)
	return cdc
}

func setCosmosEnv(chainId string) {
	switch chainId {
	case "cc-cosmos":
		return
	case "switcheochain":
		config := types.GetConfig()
		config.SetBech32PrefixForAccount("swth", "swthpub")
		config.SetBech32PrefixForValidator("swthvaloper", "swthvaloperpub")
		config.SetBech32PrefixForConsensusNode("swthvalcons", "swthvalconspub")
		config.Seal()
	case "switcheo-tradehub-1":
		config := types.GetConfig()
		config.SetBech32PrefixForAccount("swth", "swthpub")
		config.SetBech32PrefixForValidator("swthvaloper", "swthvaloperpub")
		config.SetBech32PrefixForConsensusNode("swthvalcons", "swthvalconspub")
	default:
		log.Warnf("cosmos chain id not known %s, so use default settings", chainId)
	}
}

func setUpPoly(poly *poly_go_sdk.PolySdk) error {
	poly.NewRpcClient().SetAddress(RCtx.Conf.PolyRpcAddr)
	hdr, err := poly.GetHeaderByHeight(0)
	if err != nil {
		return err
	}
	poly.SetChainId(hdr.ChainID)
	return nil
}
