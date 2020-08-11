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

package db

import (
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/cosmos/cosmos-sdk/x/bank"
	"github.com/polynetwork/cosmos-poly-module/btcx"
	"github.com/polynetwork/cosmos-poly-module/ccm"
	"github.com/polynetwork/cosmos-poly-module/ft"
	"github.com/polynetwork/cosmos-poly-module/headersync"
	"github.com/polynetwork/cosmos-poly-module/lockproxy"
	pt "github.com/polynetwork/poly/core/types"
	"github.com/stretchr/testify/assert"
	types2 "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/libs/kv"
	"github.com/tendermint/tendermint/rpc/core/types"
	"os"
	"testing"
)

var (
	tx1 = &coretypes.ResultTx{
		Hash:   []byte{1},
		Tx:     []byte{0},
		Height: 100,
		Index:  0,
		TxResult: types2.ResponseDeliverTx{
			Log: "tx1",
			Events: []types2.Event{
				types2.Event{
					Type: "gogogo",
					Attributes: []kv.Pair{
						kv.Pair{
							Key:   []byte{1},
							Value: []byte{2},
						},
					},
				},
			},
		},
	}
	tx2 = &coretypes.ResultTx{
		Hash:   []byte{2},
		Tx:     []byte{0},
		Height: 100,
		Index:  0,
	}
)

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

	//cdc.RegisterConcrete(coretypes.ResultTx{}, "cosmos-relayer/ResultTx", nil)
	return cdc
}

func TestNewDatabase(t *testing.T) {
	_, err := NewDatabase("./", NewCodecForRelayer())
	assert.NoError(t, err)

	_ = os.RemoveAll("./db.bin")
}

func TestDatabase_SetCosmosTxReproving(t *testing.T) {
	tx := &coretypes.ResultTx{
		Hash:   []byte{1, 1, 1, 1},
		Tx:     []byte{0},
		Height: 100,
		Index:  0,
	}
	db, _ := NewDatabase("./", NewCodecForRelayer())
	err := db.SetCosmosTxReproving(tx)
	assert.NoError(t, err)

	_ = os.RemoveAll("./db.bin")
}

func TestDatabase_GetCosmosTxReproving(t *testing.T) {
	//defer os.RemoveAll("./db.bin")

	db, _ := NewDatabase("./", NewCodecForRelayer())

	// save tx1 and get tx1
	err := db.SetCosmosTxReproving(tx1)
	assert.NoError(t, err)
	arr, err := db.GetCosmosTxReproving()
	assert.NoError(t, err)
	assert.Equal(t, 1, len(arr), "wrong length")
	assert.Equal(t, tx1.Hash.String(), arr[0].Hash.String())
	assert.Equal(t, false, db.cosmosTxInChanMap[tx1.Hash.String()])
	assert.Equal(t, tx1.TxResult.Events[0].Type, "gogogo")
	assert.Equal(t, tx1.TxResult.Events[0].Attributes[0].Key, []byte{1})
	assert.Equal(t, 1, db.totalReproveCosmosTx)

	// set one more tx2
	_ = db.SetCosmosTxReproving(tx2)
	arr, err = db.GetCosmosTxReproving()
	assert.NoError(t, err)
	assert.Equal(t, 2, len(arr), "wrong length")
	assert.Equal(t, tx2.Hash.String(), arr[1].Hash.String())
	assert.Equal(t, false, db.cosmosTxInChanMap[tx2.Hash.String()])
	assert.Equal(t, 2, len(db.cosmosTxInChanMap))
	assert.Equal(t, 2, db.totalReproveCosmosTx)

	// set tx1 in chan
	db.SetCosmosTxTxInChan(tx1.Hash)
	assert.Equal(t, true, db.cosmosTxInChanMap[tx1.Hash.String()])
	arr, err = db.GetCosmosTxReproving()
	assert.NoError(t, err)
	assert.Equal(t, 1, len(arr), "wrong length")
	assert.Equal(t, tx2.Hash.String(), arr[0].Hash.String())
	assert.Equal(t, false, db.cosmosTxInChanMap[tx2.Hash.String()])
	assert.Equal(t, 2, len(db.cosmosTxInChanMap))
	assert.Equal(t, 1, db.totalReproveCosmosTx)
}

func TestDatabase_DelCosmosTxReproving(t *testing.T) {
	defer os.RemoveAll("./db.bin")

	db, _ := NewDatabase("./", NewCodecForRelayer())

	_ = db.SetCosmosTxReproving(tx1)
	db.SetCosmosTxTxInChan(tx1.Hash)
	err := db.DelCosmosTxReproving(tx1.Hash)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(db.cosmosTxInChanMap))
	assert.Equal(t, 0, db.totalReproveCosmosTx)
}

func TestDatabase_SetPolyTxReproving(t *testing.T) {
	db, _ := NewDatabase("./", NewCodecForRelayer())
	err := db.SetPolyTxReproving("1111", "2222", &pt.Header{
		ChainID: 666,
		Height:  666,
	})
	assert.NoError(t, err)
	_ = os.RemoveAll("./db.bin")
}

func TestDatabase_GetPolyTxReproving(t *testing.T) {
	defer os.RemoveAll("./db.bin")

	db, _ := NewDatabase("./", NewCodecForRelayer())
	err := db.SetPolyTxReproving("1111", "2222", &pt.Header{
		ChainID: 666,
		Height:  666,
	})
	assert.NoError(t, err)
	arr, err := db.GetPolyTxReproving()
	assert.Equal(t, 1, len(arr), "wrong length")
	assert.Equal(t, "1111", arr[0].Txhash)
	assert.Equal(t, "2222", arr[0].Proof)
	assert.Equal(t, uint64(666), arr[0].Hdr.ChainID)
	assert.Equal(t, false, db.polyTxInChanMap["1111"])
	assert.Equal(t, 1, db.totalReprovePolyTx)

	_ = db.SetPolyTxReproving("3333", "4444", &pt.Header{
		ChainID: 777,
		Height:  777,
	})
	arr, err = db.GetPolyTxReproving()
	assert.NoError(t, err)
	assert.Equal(t, 2, len(arr), "wrong length")
	assert.Equal(t, "3333", arr[1].Txhash)
	assert.Equal(t, "4444", arr[1].Proof)
	assert.Equal(t, uint64(777), arr[1].Hdr.ChainID)
	assert.Equal(t, 2, db.totalReprovePolyTx)
	assert.Equal(t, 2, len(db.polyTxInChanMap))

	db.SetPolyTxTxInChan("1111")
	assert.Equal(t, true, db.polyTxInChanMap["1111"])
	arr, err = db.GetPolyTxReproving()
	assert.NoError(t, err)
	assert.Equal(t, 1, len(arr), "wrong length")
	assert.Equal(t, "3333", arr[0].Txhash)
	assert.Equal(t, "4444", arr[0].Proof)
	assert.Equal(t, uint64(777), arr[0].Hdr.ChainID)
	assert.Equal(t, 1, db.totalReprovePolyTx)
	assert.Equal(t, 2, len(db.polyTxInChanMap))
}

func TestDatabase_DelPolyTxReproving(t *testing.T) {
	defer os.RemoveAll("./db.bin")

	db, _ := NewDatabase("./", NewCodecForRelayer())
	_ = db.SetPolyTxReproving("1111", "2222", &pt.Header{
		ChainID: 666,
		Height:  666,
	})

	err := db.DelPolyTxReproving("1111")
	assert.NoError(t, err)
	assert.Equal(t, 0, len(db.polyTxInChanMap))
	assert.Equal(t, 0, db.totalReprovePolyTx)
}
