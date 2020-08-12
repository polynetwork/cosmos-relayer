<h1 align="center">COSMOS Relayer</h1>

## Introduction

Cosmos Relayer is a common relayer for chains based on COSMOS-SDK. Cosmos Relayer will relay cross-chain transaction from and to Poly. It costs gas fee on side chain and relayer must have a poly wallet which is allowed to send transactions to poly.

## Build From Source

### Prerequisites

- [Golang](https://golang.org/doc/install) version 1.14 or later

### Build

```shell
git clone https://github.com/polynetwork/cosmos-relayer.git
cd cosmos-relayer
go build -o run_cosmos_relayer cmd/run.go
```

After building the source code successfully,  you should see the executable program `run_cosmos_relayer`. 

## Usage

### Configuration

Before running relayer, you have to config it right.

```
{
  "cosmos_rpc_addr": "http://chain_based_on_cosmossdk:26657", // you side chain node RPC address
  "cosmos_wallet": "./cosmos_key", // you tendermint wallet
  "cosmos_wallet_pwd": "", // password
  "cosmos_start_height": 0, // relayer will start from this height
  "cosmos_listen_interval": 1, // interval for scanning the chain
  "cosmos_chain_id": "cosmos-chain-id", // your cosmos chain id
  "cosmos_gas_price": "0.000001stake", // gas price of side chain
  "cosmos_gas": 200000, // gas

  "poly_rpc_addr": "http://poly_rpc", // poly RPC address
  "poly_wallet": "./wallet.dat", // poly wallet which is already a registered relayer
  "poly_wallet_pwd": "", // password
  "poly_start_height": 0, // relayer will start scanning poly from this height 
  "poly_listen_interval": 1, // interval for scanning poly
  "poly_to_cosmos_key": "makeProof", // key word. no need to change

  "side_chain_id": 5, // side chain id for cross-chain
  "db_path": "./db", // DB path
  "confirm_timeout": 300, // If relayer send a tx to chain over `confirm_timeout`, it would be timeout.
  "log_level": 0 // log level: 0 TRACE, 1 DEBUG, 2 INFO, 3 ERROR, 4 FATAL
}

```

### Start Relayer

Run as follow:

```
./run_cosmos_relayer -conf=conf.json
```

