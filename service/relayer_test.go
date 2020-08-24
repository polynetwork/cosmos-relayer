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

package service

import (
	"encoding/hex"
	"fmt"
	"github.com/cosmos/cosmos-sdk/types"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/smartcontract/service/native/utils"
	"github.com/polynetwork/cosmos-poly-module/headersync"
	"github.com/polynetwork/cosmos-relayer/context"
	"github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/native/service/header_sync/cosmos"
	"github.com/stretchr/testify/assert"
	"math"
	"strings"
	"testing"
	"time"
)

func TestTOCosmosRoutine(t *testing.T) {
	conf, err := context.NewConf("/Users/zou/go/src/github.com/ontio/cosmos-relayer/conf.json")
	assert.NoError(t, err)

	err = context.InitCtx(conf)
	assert.NoError(t, err)
	//acc, _ := types.AccAddressFromBech32("cosmos1cewy8pjuz7f42j582p7emzry0g3xrl0xd9f038")
	//transfer := bank.MsgSend{FromAddress: ctx.CMAcc, ToAddress: acc,
	//	Amount: types.NewCoins(types.NewCoin("stake", types.NewInt(1)))}

	//res, err := sendCosmosTx([]types.Msg{msg})
	//assert.NoError(t, err)
	//fmt.Println(res.Hash.String())
	//param := crosschain.NewQueryCurrentHeightParams(0)
	//data, err := ctx.CMCdc.MarshalJSON(param)
	//assert.NoError(t, err)
	//
	//curr, err := ctx.CMRpcCli.ABCIQuery(QUERY_CURRENT_PATH, data)
	//assert.NoError(t, err)
	//currHeight := uint32(0)
	//if err = ctx.CMCdc.UnmarshalJSON(curr.Response.Value, &currHeight); err != nil {
	//	t.Fatal(err)
	//}
	//fmt.Println(currHeight)
	//txhash, _ := hex.DecodeString("7DEB525706C0B1E5E4351EA9540B8156611D203550AEE35D08FDB915B185F719")
	//tx, err := ctx.CMRpcCli.Tx(txhash, true)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//for _, v := range tx.TxResult.Events {
	//	fmt.Println("type:", v.Type)
	//	for _, a := range v.Attributes {
	//		fmt.Println(string(a.Key), string(a.Value))
	//	}
	//	fmt.Println("---------------------------------------")
	//}
	//
	//status, err := ctx.CMRpcCli.Status()
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//hash, err := hex.DecodeString(string(tx.TxResult.Events[2].Attributes[1].GetValue()))
	//if err != nil {
	//	t.Fatal(err)
	//}
	//fmt.Println(status.SyncInfo.LatestBlockHeight, tx.Height)
	//res, err := ctx.CMRpcCli.ABCIQueryWithOptions(ProofPath, append(crosschain.CrossChainTxDetailPrefix, hash...),
	//	client.ABCIQueryOptions{Prove: true, Height: status.SyncInfo.LatestBlockHeight - 1})
	//if err != nil {
	//	t.Fatal(err)
	//}
	//proof, err := res.Response.GetProof().Marshal()
	//if err != nil {
	//	t.Fatal(err)
	//}
	//fmt.Printf("proof: %x, height: %d\n", proof, res.Response.Height)
	//
	//prt := rootmulti.DefaultProofRuntime()
	//kp := merkle.KeyPath{}
	//kp = kp.AppendKey([]byte("lockproxy"), merkle.KeyEncodingURL)
	//kp = kp.AppendKey(res.Response.Key, merkle.KeyEncodingURL)
	//
	//h := res.Response.Height + 1
	//rb, err := ctx.CMRpcCli.Block(&h)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//err = prt.VerifyValue(res.Response.Proof, rb.Block.Header.AppHash, kp.String(), res.Response.GetValue())
	//if err != nil {
	//	t.Fatal(err)
	//}
	//fmt.Println(ctx.CMAcc.String())
	//fmt.Println(utils.OntContractAddress.ToHexString())
	//
	//status, _ := ctx.CMRpcCli.Status()
	//fmt.Println(status.SyncInfo.LatestBlockHeight)
	//
	//bp := bank.NewQueryBalanceParams(ctx.CMAcc)
	//raw, err := ctx.CMCdc.MarshalJSON(bp)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//res, err := ctx.CMRpcCli.ABCIQueryWithOptions("/custom/bank/balances", raw, client.ABCIQueryOptions{Prove: true, Height: status.SyncInfo.LatestBlockHeight - 1})
	//if err != nil {
	//	t.Fatal(err)
	//}
	//fmt.Println(res.Response.Value, res.Response.Proof)
	//
	//p := auth.NewQueryAccountParams(ctx.CMAcc)
	//raw, err = ctx.CMCdc.MarshalJSON(p)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//s, _ := ctx.CMRpcCli.Status()
	//hash, _ := hex.DecodeString("DD35F7A46E9090B9D193AE095B1F3A2B5085966A671ED0306CB94BE350935B80")
	//res, err := ctx.CMRpcCli.ABCIQueryWithOptions("/store/ccm/key", ccm.GetCrossChainTxKey(hash), client.ABCIQueryOptions{Prove: true, Height: s.SyncInfo.LatestBlockHeight - 2})
	//if err != nil {
	//	t.Fatal(err)
	//}
	//fmt.Println(hex.EncodeToString(res.Response.GetValue()))
	//res, err := ctx.CMRpcCli.Status()
	//vals, err := getValidators(res.SyncInfo.LatestBlockHeight)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//for _, v := range vals {
	//	fmt.Println(v.String(), v.VotingPower, res.ValidatorInfo.Address)
	//}
	hdr, _ := ctx.Poly.GetHeaderByHeight(73580)
	fmt.Println(hdr.Bookkeepers)
	//val, err := ctx.Poly.GetStorage(utils.HeaderSyncContractAddress.ToHexString(),
	//	append([]byte(mhcomm.CURRENT_HEADER_HEIGHT), utils.GetUint64Bytes(ccm.CurrentChainCrossChainId)...))
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//fmt.Println(utils.GetBytesUint64(val))
	//
	//val, err = ctx.Poly.GetStorage(utils.HeaderSyncContractAddress.ToHexString(),
	//	append(append([]byte("mainChain"), utils.GetUint64Bytes(6)...), utils.GetUint64Bytes(uint64(22296))...))
	//if err != nil {
	//	t.Fatal(err)
	//}
	//var header cosmos.CosmosHeader
	//err = ctx.CMCdc.UnmarshalBinaryBare(val, &header)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//fmt.Println(header.Header.Hash().String(), header.Header.Height)
}

func TestCommitGenesis(t *testing.T) {
	conf, err := context.NewConf("/Users/zou/go/src/github.com/ontio/cosmos-relayer/conf.json")
	assert.NoError(t, err)

	err = context.InitCtx(conf)
	assert.NoError(t, err)
	//
	// commit COSMOS genesis header to Poly
	h := int64(1)
	res, err := ctx.CMRpcCli.Commit(&h)
	if err != nil {
		t.Fatal(err)
	}
	vals, err := getValidators(h)
	if err != nil {
		t.Fatal(err)
	}
	ch := &cosmos.CosmosHeader{
		Header:  *res.Header,
		Commit:  res.Commit,
		Valsets: vals,
	}
	raw, err := ctx.CMCdc.MarshalBinaryBare(ch)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%s\n", hex.EncodeToString(raw))

	//curr, _ := ctx.Poly.GetCurrentBlockHeight()
	//fmt.Println(curr)
	wArr := strings.Split("/Users/zou/Desktop/work/跨链/poly-peers/wallet1.dat,/Users/zou/Desktop/work/跨链/poly-peers/wallet2.dat,/Users/zou/Desktop/work/跨链/poly-peers/wallet3.dat,/Users/zou/Desktop/work/跨链/poly-peers/wallet4.dat,/Users/zou/Desktop/work/跨链/poly-peers/wallet5.dat,/Users/zou/Desktop/work/跨链/poly-peers/wallet6.dat,/Users/zou/Desktop/work/跨链/poly-peers/wallet7.dat", ",")
	pArr := strings.Split("4cUYqGj2yib718E7ZmGQc,4cUYqGj2yib718E7ZmGQc,4cUYqGj2yib718E7ZmGQc,4cUYqGj2yib718E7ZmGQc,4cUYqGj2yib718E7ZmGQc,4cUYqGj2yib718E7ZmGQc,4cUYqGj2yib718E7ZmGQc", ",")

	accArr := make([]*poly_go_sdk.Account, len(wArr))
	for i, v := range wArr {
		accArr[i], err = context.GetAccountByPassword(ctx.Poly, v, []byte(pArr[i]))
		if err != nil {
			panic(fmt.Errorf("failed to decode no%d wallet %s with pwd %s", i, wArr[i], pArr[i]))
		}
	}

	fmt.Println(hex.EncodeToString(raw))
	txhash, err := ctx.Poly.Native.Hs.SyncGenesisHeader(context.RCtx.Conf.SideChainId, raw, accArr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(txhash.ToHexString())

	//raw, _ := hex.DecodeString("c3a14ebb3e35ad8d04fbd159559d85d5951ce03cc965ce0352610938d5fae3c6")
	//
	//aa, _ := common.Uint256ParseFromBytes(raw)
	//fmt.Println(aa.ToHexString())

	//commit Poly genesis header to COSMOS
	hdr, err := context.RCtx.Poly.GetHeaderByHeight(300000)
	if err != nil {
		t.Fatal(err)
	}
	param := &headersync.MsgSyncGenesisParam{
		Syncer:        context.RCtx.CMAcc,
		GenesisHeader: hex.EncodeToString(hdr.ToArray()),
	}
	resTx, _, err := sendCosmosTx([]types.Msg{param})
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(resTx.Hash, resTx.Log)
}

func TestStartRelay(t *testing.T) {
	conf, err := context.NewConf("/Users/zou/go/src/github.com/polynetwork/cosmos-relayer/conf.json")
	assert.NoError(t, err)

	err = context.InitCtx(conf)
	assert.NoError(t, err)

	header, err := ctx.Poly.GetHeaderByHeight(0)
	if err != nil {
		t.Fatal(err)
	}

	param := &headersync.MsgSyncGenesisParam{
		Syncer:        ctx.CMAcc,
		GenesisHeader: hex.EncodeToString(header.ToArray()),
	}
	resTx, _, err := sendCosmosTx([]types.Msg{param})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)

	res, err := ctx.CMRpcCli.Tx(resTx.Hash, true)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(res.Hash.String())

	fmt.Printf("res: %v", res.TxResult.Events)
}

func TestToCosmosRoutine(t *testing.T) {
	//config := types.GetConfig()
	//config.SetBech32PrefixForAccount(cmd.MainPrefix, cmd.MainPrefix+types.PrefixPublic)
	//config.SetBech32PrefixForValidator(cmd.MainPrefix+types.PrefixValidator+types.PrefixOperator, cmd.MainPrefix+types.PrefixValidator+types.PrefixOperator+types.PrefixPublic)
	//config.SetBech32PrefixForConsensusNode(cmd.MainPrefix+types.PrefixValidator+types.PrefixConsensus, cmd.MainPrefix+types.PrefixValidator+types.PrefixConsensus+types.PrefixPublic)
	//config.Seal()
	//_, acc, err := context.GetCosmosPrivateKey("/Users/zou/go/src/github.com/polynetwork/cosmos-relayer/cosmos_key", []byte("12345678"))
	//if err != nil {
	//	t.Fatal(err)
	//}
	//
	//fmt.Println(acc.String())
	//
	//fmt.Println(hex.EncodeToString([]byte("mpCNjy4QYAmw8eumHJRbVtt6bMDVQvPpFn")))
	a := uint64(math.MaxInt64)
	sink := common.NewZeroCopySink(nil)
	utils.EncodeVarUint(sink, a)
	val, err := utils.DecodeVarUint(common.NewZeroCopySource(sink.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(val)
}
