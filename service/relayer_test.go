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
	"github.com/polynetwork/cosmos-poly-module/headersync"
	"github.com/polynetwork/cosmos-relayer/context"
	"github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	types2 "github.com/polynetwork/poly/core/types"
	"github.com/polynetwork/poly/native/service/header_sync/cosmos"
	"github.com/stretchr/testify/assert"
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
	//a := uint64(math.MaxInt64)
	//sink := common.NewZeroCopySink(nil)
	//utils.EncodeVarUint(sink, a)
	//val, err := utils.DecodeVarUint(common.NewZeroCopySource(sink.Bytes()))
	//if err != nil {
	//	t.Fatal(err)
	//}
	//fmt.Println(val)
	raw := "000000009b915617000000008a8be062ace42d9d414bd4bdd5f9eb0e98c26f6b7ffbb69b4a1c43c522e973d8ba6f9ce33a6bad1c67f11d93d0b51c9a92a6dbfe0dd18eb84ced6c3034a70b5500000000000000000000000000000000000000000000000000000000000000002345c2204e9f1c38f833ab71ab58ea6f841440ad374183a1cbd6fb0a26e53fcedc4c475f36ff01005e159a8b139e1877fd11017b226c6561646572223a362c227672665f76616c7565223a22424148315a51375347444631356c6d487456585938674a574f4d6d3330367869632b6e72674b4d316448475a4c73436362324f48463043734d4964442b2b6f31444d6e537a70755a494e335362784d4d744a382f3070553d222c227672665f70726f6f66223a224f7244347271477258314d33743779496b355a312f6949697544686e77654761672b615358372b4557764134772f73762b6b416c7036456f3442564a72322b797a7a4b72543364502f6c30525743596a6e2b744863773d3d222c226c6173745f636f6e6669675f626c6f636b5f6e756d223a3132303030302c226e65775f636861696e5f636f6e666967223a6e756c6c7d00000000000000000000000000000000000000000623120502eb1baab602c5899282561cdaaa7aabbcdd0ccfcbc3e79793ac24acf90778f35a23120502468dd1899ed2d1cc2b829882a165a0ecb6a745af0c72eb2982d66b4311b4ef73231205038b8af6210ecfdcbcab22552ef8d8cf41c6f86f9cf9ab53d865741cfdb833f06b231205028172918540b2b512eae1872a2a2e3a28d989c60d95dab8829ada7d7dd706d658231205031e0779f5c5ccb2612352fe4a200f99d3e7758e70ba53f607c59ff22a30f678ff23120502482acb6564b19b90653f6e9c806292e8aa83f78e7a9382a24a6efe41c0c06f390642011bf5c46be4ce30c0f68a33d71b4e77bcb03501c10292844ee9397e6d58e93d982a2b9dbaa5a03717cee5a6845bc162965b7da1c658ece5efeb99dd2d007111b5c842011c84e74eee4be4c00b559dd7a5a8be12e403798ec21568287de0479e0624824fdd71249bcfd3198d22def17ee738ea1260f7d31c60654d5b733e00830942eaabe542011b88cc305573abd188b16be354067128feb9fa314d00a05203b4210344b7906c2c47323f881ca24b3362e35618588335085e51f45e51b0fb85b741b2b4bfd8638f42011b3980da5d5402befdf1f48c0d767fb8bc7bfd4c46d3cc39faea4234b2018039232239c3997c8ee67b8de3fe045e89ced0b54db039e9053d1f8a9d142534225fa442011cdcb9a09645b34efd40fd96d81fe19e233ecc582776893e2fef9a81b829dacd070e95a7df88589382e6a2dc147b1afe35995c00d93b3d3a4c9fa4dcc178e9b41c42011bf986f35f5d74e74bb809044f1256a850662f13605f577d96af7dc1e33054b613727c1033a89edbcb9144f80ed655786698f48114a9b021b346df6e83bef4aa70"
	rawB, _ := hex.DecodeString(raw)
	header := &types2.Header{}
	err := header.Deserialization(common.NewZeroCopySource(rawB))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(header.ChainID)
}
