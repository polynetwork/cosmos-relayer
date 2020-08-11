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
	"github.com/polynetwork/cosmos-poly-module/ccm"
	"github.com/polynetwork/cosmos-poly-module/headersync"
	"time"
)

const (
	PER_PAGE                    = 100 // (0, 100]
	HDR_LIMIT_PER_BATCH         = 50
	QUERY_CONSENSUS_PATH        = "/custom/" + headersync.ModuleName + "/" + headersync.QueryConsensusPeers
	COSMOS_CROSS_CHAIN_MOD_NAME = ccm.ModuleName
	RIGHT_HEIGHT_UPDATE         = "update latest height"
	COSMOS_PROOF_KEY            = "make_from_cosmos_proof"
	PROOF_PATH                  = "/store/" + ccm.ModuleName + "/key"
	TX_ALREADY_EXIST            = "already done"
	NEW_EPOCH                   = "lower than epoch switching height"
	SEQ_ERR                     = "verify correct account sequence and chain-id"
	BROADCAST_CONN_TIME_OUT     = "connection timed out"
	UTXO_NOT_ENOUGH             = "current utxo is not enoug"
)

var (
	SleepSecs = func(n int) {
		time.Sleep(time.Duration(n) * time.Second)
	}
)
