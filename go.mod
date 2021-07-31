module github.com/0chain/gosdk

require (
	github.com/ethereum/go-ethereum v1.10.3
	github.com/h2non/filetype v1.0.9
	github.com/herumi/bls-go-binary v0.0.0-20191119080710-898950e1a520
	github.com/klauspost/reedsolomon v1.9.11
	github.com/miguelmota/go-ethereum-hdwallet v0.0.1
	github.com/mitchellh/mapstructure v1.1.2
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/tyler-smith/go-bip39 v1.1.0
	go.dedis.ch/kyber/v3 v3.0.5
	go.uber.org/zap v1.15.0
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	github.com/0chain/gosdk/errors v0.0.0
)

go 1.13

replace (
	github.com/0chain/gosdk/errors => ./errors
)
