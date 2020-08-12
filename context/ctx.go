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
	"fmt"
	"github.com/cosmos/cosmos-sdk/codec"
	ctypes "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/cosmos/cosmos-sdk/x/auth/exported"
	"github.com/polynetwork/cosmos-relayer/db"
	"github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/core/types"
	"github.com/polynetwork/poly/native/service/header_sync/cosmos"
	tcrypto "github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/rpc/client"
	rpchttp "github.com/tendermint/tendermint/rpc/client/http"
	rpctypes "github.com/tendermint/tendermint/rpc/core/types"
	"sync"
)

const (
	CHAN_BUF_SIZE          = 256
	QUERY_ACC_PATH         = "/custom/acc/account"
	COSMOS_TX_NOT_IN_EPOCH = "Compare height"
)

type InfoType int

const (
	TyTx InfoType = iota
	TyHeader
	TyUpdateHeight
)

var (
	RCtx = &Ctx{}
)

func InitCtx(conf *Conf) error {
	var (
		err         error
		exportedAcc exported.Account
		gasPrice    ctypes.DecCoins
	)

	RCtx.Conf = conf
	setCosmosEnv(conf.CosmosChainId)

	// channels
	RCtx.ToCosmos = make(chan *PolyInfo, CHAN_BUF_SIZE)
	RCtx.ToPoly = make(chan *CosmosInfo, CHAN_BUF_SIZE)

	// prepare COSMOS staff
	RCtx.CMRpcCli, err = rpchttp.New(conf.CosmosRpcAddr, "/websocket")
	if err != nil {
		return fmt.Errorf("failed to new Tendermint Cli: %v", err)
	}
	if RCtx.CMPrivk, RCtx.CMAcc, err = GetCosmosPrivateKey(conf.CosmosWallet, []byte(conf.CosmosWalletPwd)); err != nil {
		return err
	}
	RCtx.CMCdc = NewCodecForRelayer()
	rawParam, err := RCtx.CMCdc.MarshalJSON(auth.NewQueryAccountParams(RCtx.CMAcc))
	if err != nil {
		return err
	}
	res, err := RCtx.CMRpcCli.ABCIQueryWithOptions(QUERY_ACC_PATH, rawParam, client.ABCIQueryOptions{Prove: true})
	if err != nil {
		return err
	}
	if !res.Response.IsOK() {
		return fmt.Errorf("failed to get response for accout-query: %v", res.Response)
	}
	if err := RCtx.CMCdc.UnmarshalJSON(res.Response.Value, &exportedAcc); err != nil {
		return fmt.Errorf("unmarshal query-account-resp failed, err: %v", err)
	}
	RCtx.CMSeq = &CosmosSeq{
		lock: sync.Mutex{},
		val:  exportedAcc.GetSequence(),
	}
	RCtx.CMAccNum = exportedAcc.GetAccountNumber()
	if gasPrice, err = ctypes.ParseDecCoins(conf.CosmosGasPrice); err != nil {
		return err
	}
	if RCtx.CMFees, err = CalcCosmosFees(gasPrice, conf.CosmosGas); err != nil {
		return err
	}
	RCtx.CMGas = conf.CosmosGas

	// prepare Poly staff
	RCtx.Poly = poly_go_sdk.NewPolySdk()
	if err := setUpPoly(RCtx.Poly); err != nil {
		return err
	}
	if RCtx.PolyAcc, err = GetAccountByPassword(RCtx.Poly, conf.PolyWallet, []byte(conf.PolyWalletPwd)); err != nil {
		return err
	}

	RCtx.Db, err = db.NewDatabase(conf.DBPath, RCtx.CMCdc)
	if err != nil {
		return err
	}

	if RCtx.CMStatus, err = NewCosmosStatus(); err != nil {
		panic(fmt.Errorf("failed to new cosmos_status: %v", err))
	}
	if RCtx.PolyStatus, err = NewPolyStatus(); err != nil {
		panic(fmt.Errorf("failed to new poly_status: %v", err))
	}

	return nil
}

type Ctx struct {
	// configuration
	Conf *Conf

	// To transfer cross chain tx from listening to relaying
	ToCosmos chan *PolyInfo
	ToPoly   chan *CosmosInfo

	// Cosmos
	CMRpcCli *rpchttp.HTTP
	CMPrivk  tcrypto.PrivKey
	CMAcc    ctypes.AccAddress
	CMSeq    *CosmosSeq
	CMAccNum uint64
	CMFees   ctypes.Coins
	CMGas    uint64
	CMCdc    *codec.Codec

	// Poly chain
	Poly    *poly_go_sdk.PolySdk
	PolyAcc *poly_go_sdk.Account

	// DB
	Db *db.Database

	// status for relayed tx
	CMStatus   *CosmosStatus
	PolyStatus *PolyStatus
}

type PolyInfo struct {
	// type 0 means only tx; type 2 means header and tx; type 1 means only header;
	Type InfoType

	// to update height of Poly on COSMOS
	Height uint32

	// tx part
	Tx *PolyTx

	// header part
	Hdr *types.Header

	// proof of header which is not during current epoch
	HeaderProof string

	// any header in current epoch can be trust anchor
	EpochAnchor string
}

type PolyTx struct {
	Height      uint32
	Proof       string
	TxHash      string
	IsEpoch     bool
	CCID        []byte
	FromChainId uint64
}

type CosmosInfo struct {
	// type 1 means header and tx; type 2 means only header;
	Type InfoType

	// to update height of chain
	Height int64

	// tx part
	Tx *CosmosTx

	// header part
	Hdrs []*cosmos.CosmosHeader
}

type CosmosTx struct {
	Tx          *rpctypes.ResultTx
	ProofHeight int64
	Proof       []byte
	PVal        []byte
}

type CosmosSeq struct {
	lock sync.Mutex
	val  uint64
}

func (seq *CosmosSeq) GetAndAdd() uint64 {
	seq.lock.Lock()
	defer func() {
		seq.val += 1
		seq.lock.Unlock()
	}()
	return seq.val
}
