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
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/polynetwork/cosmos-poly-module/ccm"
	"github.com/polynetwork/cosmos-poly-module/headersync"
	"github.com/polynetwork/cosmos-relayer/context"
	"github.com/polynetwork/cosmos-relayer/log"
	"github.com/polynetwork/poly/common"
	ccmc "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	ccm_cosmos "github.com/polynetwork/poly/native/service/cross_chain_manager/cosmos"
	mhcomm "github.com/polynetwork/poly/native/service/header_sync/common"
	"github.com/polynetwork/poly/native/service/header_sync/cosmos"
	"github.com/polynetwork/poly/native/service/utils"
	"github.com/tendermint/tendermint/crypto/merkle"
	"github.com/tendermint/tendermint/rpc/client"
	"github.com/tendermint/tendermint/rpc/core/types"
	tdmt_types "github.com/tendermint/tendermint/types"
	"strings"
	"time"
)

var (
	ctx = context.RCtx
)

// Start listen cosmos and Poly
func StartListen() {
	go PolyListen()
	go CosmosListen()
}

// Poly listen service implementation. Check blocks from height `left` to `right-1`
// and get cross-chain txs with headers that prove them. It execute once per
// `ctx.Conf.PolyListenInterval` sec. This function run as a go-routine.
func PolyListen() {
	left, tick, err := beforePolyListen()
	if err != nil {
		log.Fatalf("[ListenPoly] failed to get start height of Poly: %v", err)
		panic(err)
	}
	log.Infof("[ListenPoly] start listen Poly (start_height: %d, listen_interval: %d)",
		left+1, ctx.Conf.PolyListenInterval)

	for {
		select {
		case <-tick.C:
			epoch, err := getPolyEpochOnCosmos()
			if err != nil {
				log.Errorf("failed to get poly epoch info from COSMOS: %v", err)
				continue
			}
			right, err := ctx.Poly.GetCurrentBlockHeight()
			switch {
			case err != nil:
				log.Errorf("[ListenPoly] failed to get height of Poly, retry after %d sec: %v",
					ctx.Conf.PolyListenInterval, err)
				continue
			case right-left == 0:
				continue
			case right <= epoch.Height:
				continue
			}

			if err := reprovePolyTx(epoch.Height); err != nil {
				log.Errorf("[PolyReprove] failed to reprove: %v", err)
				continue
			}
			for h := left + 1; h <= right; h++ {
				log.Tracef("[ListenPoly] checking poly height %d", h)
				count, err := checkPolyHeight(h, epoch.Height)
				if err != nil {
					log.Errorf("[ListenPoly] failed to reach info of Poly when height is %d, retry after 10 sec: %v", h, err)
					context.SleepSecs(10)
					h--
					continue
				}
				if count > 0 {
					log.Debugf("[ListenPoly] found %d cross chain tx to COSMOS when height %d", count, h-1)
				}
			}

			left = right
		}
	}
}

// Prepare start height and ticker when init service
func beforePolyListen() (uint32, *time.Ticker, error) {
	// get current Poly height from cosmos
	cps, err := getPolyEpochOnCosmos()
	if err != nil {
		return 0, nil, err
	}
	currHeight := cps.Height
	if currHeight > 0 {
		currHeight--
	}
	log.Debugf("beforePolyListen, ( poly height on COSMOS: %d )", currHeight)

	// check latest height from db
	if dbh := ctx.Db.GetPolyHeight(); dbh > currHeight {
		log.Debugf("beforePolyListen, ( poly height in DB: %d )", dbh)
		currHeight = dbh
	}
	if ctx.Conf.PolyStartHeight != 0 {
		currHeight = ctx.Conf.PolyStartHeight
	}
	return currHeight, time.NewTicker(time.Duration(ctx.Conf.PolyListenInterval) * time.Second), nil
}

// Check height `h` to catch cross-chain txs and headers to prove them.
func checkPolyHeight(h, epochHeight uint32) (int, error) {
	var (
		cnt        int
		hp, anchor string
		prepared   bool
	)

	prepare := func() error {
		hdr, err := ctx.Poly.GetHeaderByHeight(epochHeight + 1)
		if err != nil {
			return err
		}
		anchor = hex.EncodeToString(hdr.ToArray())
		mp, err := ctx.Poly.GetMerkleProof(h, epochHeight+1)
		if err != nil {
			return err
		}
		hp = mp.AuditPath
		prepared = true
		return nil
	}

	header, err := ctx.Poly.GetHeaderByHeight(h)
	if err != nil {
		return 0, err
	}
	events, err := ctx.Poly.GetSmartContractEventByBlock(h - 1)
	if err != nil {
		return 0, err
	}
	for _, e := range events {
		for _, n := range e.Notify {
			states, ok := n.States.([]interface{})
			if !ok {
				continue
			}
			name, ok := states[0].(string)
			if ok && name == ctx.Conf.PolyToCosmosKey &&
				uint64(states[2].(float64)) == ctx.Conf.SideChainId {
				if h < epochHeight && !prepared {
					if err = prepare(); err != nil {
						return 0, err
					}
				}
				proof, _ := ctx.Poly.GetCrossStatesProof(h-1, states[5].(string)) // TODO: log
				rawProof, _ := hex.DecodeString(proof.AuditPath)

				src := common.NewZeroCopySource(rawProof)
				val, _ := src.NextVarBytes()
				merkleValue := new(ccmc.ToMerkleValue)
				_ = merkleValue.Deserialization(common.NewZeroCopySource(val))

				// check if this cross-chain tx already committed on COSMOS
				res, err := ctx.CMRpcCli.ABCIQuery(context.ProofPath, ccm.GetDoneTxKey(merkleValue.FromChainID,
					merkleValue.MakeTxParam.CrossChainID))
				if err != nil || res == nil || res.Response.GetValue() != nil {
					continue
				}

				ctx.ToCosmos <- &context.PolyInfo{
					Type: context.TyTx,
					Hdr:  header,
					Tx: &context.PolyTx{
						Height:      h - 1,
						Proof:       hex.EncodeToString(rawProof),
						TxHash:      e.TxHash,
						IsEpoch:     header.NextBookkeeper != common.ADDRESS_EMPTY,
						CCID:        merkleValue.MakeTxParam.CrossChainID,
						FromChainId: merkleValue.FromChainID,
					},
					EpochAnchor: anchor,
					HeaderProof: hp,
				}
				cnt++
			}
		}
	}

	// send header if consensus period changed and no cross-chain tx found
	if header.NextBookkeeper != common.ADDRESS_EMPTY && cnt == 0 && h > epochHeight {
		ctx.ToCosmos <- &context.PolyInfo{
			Type: context.TyHeader,
			Hdr:  header,
		}
	}

	// mark this height that we already check
	ctx.ToCosmos <- &context.PolyInfo{
		Type:   context.TyUpdateHeight,
		Height: h,
	}

	return cnt, nil
}

func reprovePolyTx(epochHeight uint32) error {
	arr, err := ctx.Db.GetPolyTxReproving()
	if err != nil {
		return err
	}
	if len(arr) == 0 {
		return nil
	}
	hdr, err := ctx.Poly.GetHeaderByHeight(epochHeight + 1)
	if err != nil {
		return err
	}
	anchor := hex.EncodeToString(hdr.ToArray())
	for _, v := range arr {
		mp, err := ctx.Poly.GetMerkleProof(v.Hdr.Height, epochHeight+1)
		if err != nil {
			return err
		}
		ctx.ToCosmos <- &context.PolyInfo{
			Type: context.TyTx,
			Hdr:  v.Hdr,
			Tx: &context.PolyTx{
				Height:  v.Hdr.Height - 1,
				Proof:   v.Proof,
				TxHash:  v.Txhash,
				IsEpoch: false,
			},
			EpochAnchor: anchor,
			HeaderProof: mp.AuditPath,
		}
		ctx.Db.SetPolyTxTxInChan(v.Txhash)
	}

	return nil
}

// Cosmos listen service implementation. Check the blocks of COSMOS from height
// `left` to height `right`, commit the cross-chain txs and headers to prove txs
// to chain Poly. It execute once per `ctx.Conf.CosmosListenInterval` sec. And update
// height `left` `right` after execution for next round. This function will run
// as a go-routine.
func CosmosListen() {
	left, tick, err := beforeCosmosListen()
	if err != nil {
		log.Fatalf("[ListenCosmos] failed to get start height of Cosmos: %v", err)
		panic(err)
	}
	log.Infof("[ListenCosmos] start listen Cosmos (start_height: %d, listen_interval: %d)", left+1,
		ctx.Conf.CosmosListenInterval)

	lastRight := left
	for {
		select {
		case <-tick.C:
			status, err := ctx.CMRpcCli.Status()
			switch {
			case err != nil:
				log.Errorf("[ListenCosmos] failed to get height of COSMOS, retry after %d sec: %v",
					ctx.Conf.CosmosListenInterval, err)
				continue
			case status.SyncInfo.LatestBlockHeight-1 <= lastRight:
				continue
			}
			right := status.SyncInfo.LatestBlockHeight - 1
			hdr, err := getCosmosHdr(right)
			if err != nil {
				log.Errorf("[ListenCosmos] failed to get %d header to get proof, retry after %d sec: %v",
					right, ctx.Conf.CosmosListenInterval, err)
				continue
			}
			if !bytes.Equal(hdr.Header.ValidatorsHash, hdr.Header.NextValidatorsHash) {
				log.Debugf("[ListenCosmos] header at %d is epoch switching point, so continue loop", hdr.Header.Height)
				lastRight = right
				continue
			}

			// let first element of infoArr be the info for epoch switching headers.
			infoArr := make([]*context.CosmosInfo, 1)
			infoArr[0] = &context.CosmosInfo{
				Type: context.TyHeader,
				Hdrs: make([]*cosmos.CosmosHeader, 0),
			}
			for h := left + 1; h <= right; h++ {
				infoArrTemp, err := checkCosmosHeight(h, hdr, infoArr, &right)
				if err != nil {
					// If error happen, we should check this height again.
					h--
					if strings.Contains(err.Error(), context.RightHeightUpdate) {
						// Can't get proof from height `right-1`, update right to the latest.
						log.Debugf("[ListenCosmos] %s", err.Error())
						continue
					}
					// some error happen, could be some network error or COSMOS full node error.
					log.Errorf("[ListenCosmos] failed to fetch info from COSMOS, retry after 10 sec: %v", err)
					context.SleepSecs(10)
					continue
				}
				infoArr = infoArrTemp
			}
			infoArr = reproveCosmosTx(infoArr, hdr)

			for i, v := range infoArr {
				if i == 0 && len(v.Hdrs) == 0 {
					continue
				}
				ctx.ToPoly <- v
			}
			cnt := 0
			for _, v := range infoArr {
				switch v.Type {
				case context.TyTx:
					cnt++
				}
			}
			if cnt > 0 {
				log.Debugf("[ListenCosmos] found %d cross chain tx to Poly [%d, %d]", cnt, left, right-1)
			}
			ctx.ToPoly <- &context.CosmosInfo{
				Type:   context.TyUpdateHeight,
				Height: right,
			}
			lastRight = right
			left = right
		}
	}
}

// Prepare start height and ticker when init service
func beforeCosmosListen() (int64, *time.Ticker, error) {
	val, err := ctx.Poly.GetStorage(utils.HeaderSyncContractAddress.ToHexString(),
		append([]byte(mhcomm.EPOCH_SWITCH), utils.GetUint64Bytes(ctx.Conf.SideChainId)...))
	if err != nil {
		return 0, nil, err
	}
	info := &cosmos.CosmosEpochSwitchInfo{}
	if err = info.Deserialization(common.NewZeroCopySource(val)); err != nil {
		return 0, nil, err
	}
	currHeight := info.Height
	if currHeight > 1 {
		currHeight--
	}
	log.Debugf("beforeCosmosListen, ( cosmos height on Poly: %d )", currHeight)
	if dbh := ctx.Db.GetCosmosHeight(); dbh > currHeight {
		log.Debugf("beforeCosmosListen, ( cosmos height in DB: %d )", dbh)
		currHeight = dbh
	}
	if ctx.Conf.CosmosStartHeight != 0 {
		currHeight = ctx.Conf.CosmosStartHeight
	}
	return currHeight, time.NewTicker(time.Duration(ctx.Conf.CosmosListenInterval) * time.Second), nil
}

// Fetch header at h and check tx at h-1.
//
// Put header to `hdrArr` and txs to `txArr`. Get proof from height `heightToGetProof`.
// `headersToRelay` record all hdrs need to relay. When need to update new height to
// get proof, relayer update `rightPtr` and return.
func checkCosmosHeight(h int64, hdrToVerifyProof *cosmos.CosmosHeader, infoArr []*context.CosmosInfo, rightPtr *int64) ([]*context.CosmosInfo, error) {
	query := getTxQuery(h - 1)
	res, err := ctx.CMRpcCli.TxSearch(query, true, 1, context.PerPage, "asc")
	if err != nil {
		return infoArr, err
	}

	rc, err := ctx.CMRpcCli.Commit(&h)
	if err != nil {
		return infoArr, err
	}
	if !bytes.Equal(rc.Header.ValidatorsHash, rc.Header.NextValidatorsHash) {
		vSet, err := getValidators(h)
		if err != nil {
			return infoArr, err
		}
		hdr := &cosmos.CosmosHeader{
			Header:  *rc.Header,
			Commit:  rc.Commit,
			Valsets: vSet,
		}
		val, _ := ctx.Poly.GetStorage(utils.CrossChainManagerContractAddress.ToHexString(),
			append(append([]byte(mhcomm.EPOCH_SWITCH), utils.GetUint64Bytes(ctx.Conf.SideChainId)...),
				utils.GetUint64Bytes(uint64(h))...))
		// check if this header is not committed on Poly
		if val == nil || len(val) == 0 {
			infoArr[0].Hdrs = append(infoArr[0].Hdrs, hdr)
		}
	}
	if res.TotalCount == 0 {
		return infoArr, nil
	}

	// get tx from pages
	heightToGetProof := *rightPtr - 1
	pages := ((res.TotalCount - 1) / context.PerPage) + 1
	for p := 1; p <= pages; p++ {
		// already have page 1
		if p > 1 {
			if res, err = ctx.CMRpcCli.TxSearch(query, true, p, context.PerPage, "asc"); err != nil {
				return infoArr, err
			}
		}
		// get proof for every tx, and add them to txArr prepared to commit
		for _, tx := range res.Txs {
			hash := getKeyHash(tx)
			res, _ := ctx.CMRpcCli.ABCIQueryWithOptions(context.ProofPath, ccm.GetCrossChainTxKey(hash),
				client.ABCIQueryOptions{Prove: true, Height: heightToGetProof})
			if res == nil || res.Response.GetValue() == nil {
				// If get the proof failed, that could means the header of height `heightToGetProof`
				// is already pruned. And the cosmos node already delete the data on
				// `heightToGetProof`. We need to update the height `right`, and check this height
				// `h` again
				for {
					status, err := ctx.CMRpcCli.Status()
					if err != nil {
						log.Errorf("failed to get status and could be something wrong with RPC: %v", err)
						continue
					}
					hdrToVerifyProof, err = getCosmosHdr(status.SyncInfo.LatestBlockHeight - 1)
					if err != nil {
						log.Errorf("failed to get cosmos header info and could be something wrong with RPC: %v", err)
						continue
					}
					*rightPtr = status.SyncInfo.LatestBlockHeight - 1
					if bytes.Equal(hdrToVerifyProof.Header.ValidatorsHash, hdrToVerifyProof.Header.NextValidatorsHash) {
						break
					}
					context.SleepSecs(1)
				}
				return infoArr, fmt.Errorf("%s from %d to %d", context.RightHeightUpdate, heightToGetProof+1, *rightPtr)
			}
			proof, _ := res.Response.Proof.Marshal()

			kp := merkle.KeyPath{}
			kp = kp.AppendKey([]byte(context.CosmosCrossChainModName), merkle.KeyEncodingURL)
			kp = kp.AppendKey(res.Response.Key, merkle.KeyEncodingURL)
			pv, _ := ctx.CMCdc.MarshalBinaryBare(&ccm_cosmos.CosmosProofValue{
				Kp:    kp.String(),
				Value: res.Response.GetValue(),
			})

			txParam := new(ccmc.MakeTxParam)
			_ = txParam.Deserialization(common.NewZeroCopySource(res.Response.GetValue()))

			// check if this cross-chain tx already committed on Poly
			// If we don't check, relayer will commit a new header to prove it.
			// And in the end, that header is committed for nothing because this tx
			// already committed
			val, _ := ctx.Poly.GetStorage(utils.CrossChainManagerContractAddress.ToHexString(),
				append(append([]byte(ccmc.DONE_TX), utils.GetUint64Bytes(ctx.Conf.SideChainId)...),
					txParam.CrossChainID...))
			if val != nil && len(val) != 0 {
				continue
			}
			tx.TxResult.Data = txParam.CrossChainID
			infoArr = append(infoArr, &context.CosmosInfo{
				Type: context.TyTx,
				Tx: &context.CosmosTx{
					Tx:          tx,
					ProofHeight: res.Response.Height,
					Proof:       proof,
					PVal:        pv,
				},
				Hdrs: []*cosmos.CosmosHeader{hdrToVerifyProof},
			})
		}
	}

	return infoArr, nil
}

func reproveCosmosTx(infoArr []*context.CosmosInfo, hdrToVerifyProof *cosmos.CosmosHeader) []*context.CosmosInfo {
	arr, err := ctx.Db.GetCosmosTxReproving()
	if err != nil {
		panic(fmt.Errorf("[ReProve] failed to get reproving cosmos tx: %v", err))
	}
	if arr == nil || len(arr) == 0 {
		return infoArr
	}
	log.Infof("[ReProve] total %d cosmos tx to reprove", len(arr))

	for i := 0; i < len(arr); i++ {
		tx := arr[i]
		hash := getKeyHash(tx)
		res, err := ctx.CMRpcCli.ABCIQueryWithOptions(context.ProofPath, ccm.GetCrossChainTxKey(hash),
			client.ABCIQueryOptions{Prove: true, Height: hdrToVerifyProof.Header.Height - 1})
		if err != nil || res == nil || res.Response.GetValue() == nil {
			log.Errorf("[ReProve] failed to query proof and could be something wrong with RPC: %v", err)
			return infoArr
		}

		kp := merkle.KeyPath{}
		kp = kp.AppendKey([]byte(context.CosmosCrossChainModName), merkle.KeyEncodingURL)
		kp = kp.AppendKey(res.Response.Key, merkle.KeyEncodingURL)
		pv, _ := ctx.CMCdc.MarshalBinaryBare(&ccm_cosmos.CosmosProofValue{
			Kp:    kp.String(),
			Value: res.Response.GetValue(),
		})

		proof, _ := res.Response.GetProof().Marshal()
		log.Debugf("[ReProve] repove cosmos tx %s with height %d and header %d",
			tx.Hash.String(), res.Response.Height, hdrToVerifyProof.Header.Height)

		txParam := new(ccmc.MakeTxParam)
		_ = txParam.Deserialization(common.NewZeroCopySource(res.Response.GetValue()))
		val, _ := ctx.Poly.GetStorage(utils.CrossChainManagerContractAddress.ToHexString(),
			append(append([]byte(ccmc.DONE_TX), utils.GetUint64Bytes(ctx.Conf.SideChainId)...),
				txParam.CrossChainID...))
		if val != nil && len(val) != 0 {
			if err = ctx.Db.DelCosmosTxReproving(tx.Hash); err != nil {
				panic(err)
			}
		}

		infoArr = append(infoArr, &context.CosmosInfo{
			Type: context.TyTx,
			Tx: &context.CosmosTx{
				Tx:          tx,
				ProofHeight: res.Response.Height,
				Proof:       proof,
				PVal:        pv,
			},
			Hdrs: []*cosmos.CosmosHeader{hdrToVerifyProof},
		})
		ctx.Db.SetCosmosTxTxInChan(tx.Hash)
	}
	return infoArr
}

func getTxQuery(h int64) string {
	return fmt.Sprintf("tx.height=%d AND make_from_cosmos_proof.status='1'", h)
}

func getValidators(h int64) ([]*tdmt_types.Validator, error) {
	p := 1
	vSet := make([]*tdmt_types.Validator, 0)
	for {
		res, err := ctx.CMRpcCli.Validators(&h, p, 100)
		if err != nil {
			if strings.Contains(err.Error(), "page should be within") {
				return vSet, nil
			}
			return nil, err
		}
		// In case tendermint don't give relayer the right error
		if len(res.Validators) == 0 {
			return vSet, nil
		}
		vSet = append(vSet, res.Validators...)
		p++
	}
}

func getCosmosHdr(h int64) (*cosmos.CosmosHeader, error) {
	rc, err := ctx.CMRpcCli.Commit(&h)
	if err != nil {
		return nil, fmt.Errorf("failed to get Commit of height %d: %v", h, err)
	}
	vSet, err := getValidators(h)
	if err != nil {
		return nil, fmt.Errorf("failed to get Validators of height %d: %v", h, err)
	}
	return &cosmos.CosmosHeader{
		Header:  *rc.Header,
		Commit:  rc.Commit,
		Valsets: vSet,
	}, nil
}

func getPolyEpochOnCosmos() (*headersync.ConsensusPeers, error) {
	data, err := ctx.CMCdc.MarshalJSON(headersync.NewQueryConsensusPeersParams(ctx.Poly.ChainId))
	if err != nil {
		return nil, err
	}
	res, err := ctx.CMRpcCli.ABCIQuery(context.QueryConsensusPath, data)
	if err != nil {
		return nil, err
	}
	if res == nil || len(res.Response.Value) == 0 {
		return nil, fmt.Errorf("current height of Poly on COSMOS not set")
	}
	cps := &headersync.ConsensusPeers{}
	if err = cps.Deserialization(common.NewZeroCopySource(res.Response.GetValue())); err != nil {
		return nil, err
	}
	return cps, nil
}

func getKeyHash(tx *coretypes.ResultTx) []byte {
	var hash []byte
	for _, e := range tx.TxResult.Events {
		if e.Type == context.CosmosProofKey {
			hash, _ = hex.DecodeString(string(e.Attributes[2].Value))
			break
		}
	}

	return hash
}
