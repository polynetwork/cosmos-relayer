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
	"encoding/hex"
	"fmt"
	"github.com/polynetwork/cosmos-poly-module/ccm"
	"github.com/polynetwork/cosmos-relayer/db"
	"github.com/polynetwork/cosmos-relayer/log"
	"github.com/polynetwork/poly/common"
	ccmc "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"github.com/polynetwork/poly/native/service/utils"
	"github.com/tendermint/tendermint/libs/bytes"
	rpctypes "github.com/tendermint/tendermint/rpc/core/types"
	"strings"
	"sync"
	"time"
)

func NewCosmosStatus() (*CosmosStatus, error) {
	m := &sync.Map{}
	_, err := RCtx.Db.LoadCosmosStatus(m)
	if err != nil {
		return nil, err
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	return &CosmosStatus{
		Txs: m,
		Wg:  wg,
	}, nil
}

type CosmosStatus struct {
	Txs             *sync.Map // TODO: record a start time to test if it's not confirm for a long time, that could be tx lost
	Wg              *sync.WaitGroup
	IsBlocked       bool
	PolyEpochHeight uint32
}

func (s *CosmosStatus) AddTx(hash bytes.HexBytes, info *PolyInfo) error {
	pph := &db.PolyProofAndHeader{
		Txhash:      info.Tx.TxHash,
		Hdr:         info.Hdr,
		Proof:       info.Tx.Proof,
		CCID:        info.Tx.CCID,
		FromChainId: info.Tx.FromChainId,
	}
	if err := RCtx.Db.SetTxToCosmosStatus(hash, pph); err != nil {
		return err
	}
	s.Txs.Store(hash.String(), pph)
	return nil
}

func (s *CosmosStatus) DelTx(hash bytes.HexBytes) error {
	if err := RCtx.Db.DelTxInCosmosStatus(hash); err != nil {
		return err
	}
	s.Txs.Delete(hash.String())
	return nil
}

func (s *CosmosStatus) Len() int {
	var l int
	s.Txs.Range(func(key, value interface{}) bool {
		l++
		return true
	})
	return l
}

// TODO: 交易丢失了怎么办，会一直循环查找地！！
func (s *CosmosStatus) Check() {
	tick := time.NewTicker(time.Second)
	var resTx *rpctypes.ResultTx
	for range tick.C {
		kArr := make([]bytes.HexBytes, 0)
		vArr := make([]*db.PolyProofAndHeader, 0)
		s.Txs.Range(func(key, value interface{}) bool {
			k, _ := hex.DecodeString(key.(string))
			kArr = append(kArr, k)
			vArr = append(vArr, value.(*db.PolyProofAndHeader))
			return true
		})
		if s.IsBlocked && len(kArr) == 0 {
			s.IsBlocked = false
			s.Wg.Done()
		}
		for i, v := range kArr {
			resTx, _ = RCtx.CMRpcCli.Tx(v, false)
			if resTx == nil {
				continue
			}
			if resTx.Height > 0 {
				if resTx.TxResult.Code == 0 {
					log.Infof("[Cosmos Status] cosmso tx %s is confirmed on block (height: %d) and success. ",
						v.String(), resTx.Height)
				} else {
					if strings.Contains(resTx.TxResult.Log, COSMOS_TX_NOT_IN_EPOCH) {
						log.Debugf("[Cosmos Status] cosmso tx %s is failed and this proof %s need reprove. ",
							v.String(), vArr[i].Proof)
						if err := RCtx.Db.SetPolyTxReproving(vArr[i].Txhash, vArr[i].Proof, vArr[i].Hdr); err != nil {
							panic(err)
						}
					} else {
						if res, _ := RCtx.CMRpcCli.ABCIQuery(PROOF_PATH, ccm.GetDoneTxKey(vArr[i].FromChainId, vArr[i].CCID)); res != nil && res.Response.GetValue() != nil {
							log.Infof("[Cosmos Status] this poly tx %s is already committed, "+
								"so delete it cosmos_txhash %s: (from_chain_id: %d, ccid: %s)",
								vArr[i].Txhash, v.String(), vArr[i].FromChainId, hex.EncodeToString(vArr[i].CCID))
						} else {
							log.Errorf("[Cosmos Status] cosmso tx %s is confirmed on block (height: %d) "+
								"and failed (Log: %s). ", v.String(), resTx.Height, resTx.TxResult.Log)
						}
					}
				}
				if err := s.DelTx(v); err != nil {
					panic(err)
				}
				if err := RCtx.Db.DelPolyTxReproving(vArr[i].Txhash); err != nil {
					panic(err)
				}
			}
		}
	}
}

func (s *CosmosStatus) Show() {
	tick := time.NewTicker(30 * time.Second)
	for range tick.C {
		str := "unconfirmed tx \n[\n%s\n] total %d tx is not confirmed"
		strs := make([]string, 0)
		l := 0
		s.Txs.Range(func(key, value interface{}) bool {
			strs = append(strs, fmt.Sprintf("( txhash: %s, poly_tx: %s )",
				key.(string), value.(*db.PolyProofAndHeader).Txhash))
			l++
			return true
		})
		if l > 0 {
			log.Infof("[Cosmos Status] %s ", fmt.Sprintf(str, strings.Join(strs, "\n"), l))
		}
	}
}

func NewPolyStatus() (*PolyStatus, error) {
	m := &sync.Map{}
	_, err := RCtx.Db.LoadPolyStatus(m)
	if err != nil {
		return nil, err
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	return &PolyStatus{
		Txs: m,
		Wg:  wg,
	}, nil
}

type PolyStatus struct {
	Txs               *sync.Map
	Wg                *sync.WaitGroup
	IsBlocked         bool
	CosmosEpochHeight int64
}

func (s *PolyStatus) AddTx(hash common.Uint256, rtx *rpctypes.ResultTx) error {
	if err := RCtx.Db.SetTxToPolyStatus(hash, rtx); err != nil {
		return err
	}
	s.Txs.Store(hash, rtx)
	return nil
}

func (s *PolyStatus) DelTx(hash common.Uint256) error {
	if err := RCtx.Db.DelTxInPolyStatus(hash); err != nil {
		return err
	}
	s.Txs.Delete(hash)
	return nil
}

func (s *PolyStatus) Check() {
	tick := time.NewTicker(time.Second)
	for range tick.C {
		kArr := make([]common.Uint256, 0)
		vArr := make([]*rpctypes.ResultTx, 0)
		s.Txs.Range(func(key, value interface{}) bool {
			kArr = append(kArr, key.(common.Uint256))
			vArr = append(vArr, value.(*rpctypes.ResultTx))
			return true
		})
		if s.IsBlocked && len(kArr) == 0 {
			s.IsBlocked = false
			s.Wg.Done()
		}
		for i, v := range kArr {
			// TODO: maybe check if tx still in mempool
			txHash := v.ToHexString()
			//state, _ := RCtx.Poly.GetMemPoolTxState(txHash)
			//state.State[0].
			h, _ := RCtx.Poly.GetBlockHeightByTxHash(txHash)
			if h == 0 {
				continue
			}
			e, err := RCtx.Poly.GetSmartContractEvent(txHash)
			if err != nil || e == nil {
				continue
			}
			switch e.State {
			case byte(0):
				if val, _ := RCtx.Poly.GetStorage(utils.CrossChainManagerContractAddress.ToHexString(),
					append(append([]byte(ccmc.DONE_TX), utils.GetUint64Bytes(RCtx.Conf.SideChainId)...),
						vArr[i].TxResult.Data...)); val != nil && len(val) != 0 {
					if err := RCtx.Db.DelCosmosTxReproving(vArr[i].Hash); err != nil {
						panic(err)
					}
					log.Infof("[Poly Status] cosmos tx %s is already committed and confirmed, "+
						"so delete poly_txhash %s: (cross_chain_id: %s)",
						vArr[i].Hash.String(), txHash, hex.EncodeToString(vArr[i].TxResult.Data))
				} else {
					if err := RCtx.Db.SetCosmosTxReproving(vArr[i]); err != nil {
						panic(err)
					}
					log.Debugf("[Poly Status] poly tx %s execute failed, reprove it!", e.TxHash)
				}
			case byte(1):
				if err = RCtx.Db.DelCosmosTxReproving(vArr[i].Hash); err != nil {
					panic(err)
				}
				log.Infof("[Poly Status] poly tx %s is confirmed on block (height: %d) and success. ",
					e.TxHash, h)
			}
			if err = RCtx.PolyStatus.DelTx(v); err != nil {
				panic(err)
			}
		}
	}
}

func (s *PolyStatus) Len() int {
	var l int
	s.Txs.Range(func(key, value interface{}) bool {
		l++
		return true
	})
	return l
}

func (s *PolyStatus) Show() {
	tick := time.NewTicker(30 * time.Second)
	for range tick.C {
		str := "unconfirmed tx \n[\n%s] total %d tx is not confirmed"
		strs := make([]string, 0)
		l := 0
		s.Txs.Range(func(key, value interface{}) bool {
			hash := key.(common.Uint256)
			strs = append(strs, fmt.Sprintf("( txhash: %s, Cosmos_tx: %s )",
				hash.ToHexString(), value.(*rpctypes.ResultTx).Hash.String()))
			l++
			return true
		})
		if l > 0 {
			log.Infof("[Poly Status] %s ", fmt.Sprintf(str, strings.Join(strs, "\n"), l))
		}
	}
}
