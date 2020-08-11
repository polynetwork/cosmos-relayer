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
	"encoding/json"
	"io/ioutil"
)

type Conf struct {
	CosmosRpcAddr        string `json:"cosmos_rpc_addr"`
	CosmosWallet         string `json:"cosmos_wallet"`
	CosmosWalletPwd      string `json:"cosmos_wallet_pwd"`
	CosmosStartHeight    int64  `json:"cosmos_start_height"`
	CosmosListenInterval int    `json:"cosmos_listen_interval"`
	CosmosChainId        string `json:"cosmos_chain_id"`
	CosmosGasPrice       string `json:"cosmos_gas_price"`
	CosmosGas            uint64 `json:"cosmos_gas"`

	PolyRpcAddr        string `json:"poly_rpc_addr"`
	PolyWallet         string `json:"poly_wallet"`
	PolyWalletPwd      string `json:"poly_wallet_pwd"`
	PolyStartHeight    uint32 `json:"poly_start_height"`
	PolyListenInterval int    `json:"poly_listen_interval"`
	PolyToCosmosKey    string `json:"poly_to_cosmos_key"`

	SideChainId    uint64 `json:"side_chain_id"`
	DBPath         string `json:"db_path"`
	ConfirmTimeout int    `json:"confirm_timeout"`

	LogLevel int `json:"log_level"`
}

func NewConf(file string) (*Conf, error) {
	conf := &Conf{}
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, conf); err != nil {
		return nil, err
	}
	return conf, nil
}
