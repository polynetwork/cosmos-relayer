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

package main

import (
	"flag"
	"fmt"
	"github.com/polynetwork/cosmos-relayer/context"
	"github.com/polynetwork/cosmos-relayer/log"
	"github.com/polynetwork/cosmos-relayer/service"
	"github.com/polynetwork/poly/common/password"
	"os"
)

var (
	confPath  string
	orcPwd    string
	cosmosPwd string
)

func init() {
	flag.StringVar(&confPath, "conf", "./conf.json", "configuration file for cosmos relayer")
	flag.StringVar(&orcPwd, "orcpwd", "", "orc wallet password")
	flag.StringVar(&cosmosPwd, "cosmospwd", "", "cosmos wallet password")
}

func main() {
	flag.Parse()

	conf, err := context.NewConf(confPath)
	if err != nil {
		log.Fatalf("failed to generate configuration object: %v", err)
		panic(err)
	}

	log.InitLog(conf.LogLevel, os.Stdout)

	// If not set by flag, try to get pwd from configuration file.
	if orcPwd != "" {
		conf.PolyWalletPwd = orcPwd
	} else if conf.PolyWalletPwd == "" {
		// If not set by configuration file, let user to input pwd
		fmt.Println("enter your polygon wallet password:")
		pwd, err := password.GetPassword()
		if err != nil {
			log.Fatalf("password is not found in config file and enter password failed: %v", err)
			panic(err)
		}
		conf.PolyWalletPwd = string(pwd)
		fmt.Println("done")
	}

	if cosmosPwd != "" {
		conf.CosmosWalletPwd = cosmosPwd
	} else if conf.CosmosWalletPwd == "" {
		fmt.Println("enter your COSMOS wallet password:")
		pwd, err := password.GetPassword()
		if err != nil {
			log.Fatalf("password is not found in config file and enter password failed: %v", err)
			panic(err)
		}
		conf.CosmosWalletPwd = string(pwd)
		fmt.Println("done")
	}

	// all tools and info hold by context object.
	if err = context.InitCtx(conf); err != nil {
		log.Fatalf("failed to init context: %v", err)
		panic(err)
	}

	log.Infof("using acc: (cosmos: %s, poly: %s)", context.RCtx.CMAcc.String(), context.RCtx.PolyAcc.Address.ToBase58())

	// start two services.
	// listen service try to find cross-chain txs and headers.
	// relay service relay all txs and headers found by listen service.
	// they communicate by channels.
	service.StartListen()
	service.StartRelay()

	service.CheckTx()

	log.Info("cosmos relayer start")
	select {}
}
