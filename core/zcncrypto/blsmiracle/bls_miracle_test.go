package blsmiracle

import (
	"bytes"
	"fmt"
	"github.com/0chain/gosdk/core/zcncrypto"
	herumi "github.com/herumi/bls-go-binary/bls"
	"github.com/stretchr/testify/assert"
	"github.com/tyler-smith/go-bip39"
	"testing"
)

func TestKeyGeneration2(t *testing.T) {
	var err error
	password := "0chain-client-split-key"
	//entropy, err := bip39.NewEntropy(256)
	//assert.Nil(t, err, "Generating entropy failed")

	//mnemonics, err := bip39.NewMnemonic(entropy)
	//assert.Nil(t, err, "Generating mnemonic failed")
	mnemonics := "special extra copper dwarf shoe stumble receive find design bounce bridge smile together expect crack hole knock page stamp swamp action negative bulb danger"
	fmt.Printf(mnemonics)
	fmt.Printf("\n")

	seed := bip39.NewSeed(mnemonics, password)

	// generating bls
	err = herumi.Init(herumi.CurveFp254BNb)
	assert.Nil(t, err, "Unable to init herumi")
	cryptoScheme := &zcncrypto.HerumiScheme{}
	wallet, err := cryptoScheme.GenerateKeysWithEth(mnemonics, password)
	assert.Nil(t, err, "Unable to GenerateKeys")

	fmt.Printf("Private key : ")
	fmt.Printf("\n")
	fmt.Printf(wallet.Keys[0].PrivateKey)
	fmt.Printf("\n")
	fmt.Printf("Public  key : ")
	fmt.Printf(wallet.Keys[0].PublicKey)
	fmt.Printf("\n")

	err = Init()
	assert.Nil(t, err, "Unable to init blsmiracle")
	r := bytes.NewReader(seed)
	SetRandFunc(r)
	secrKey := NewSecretKey()
	secrKey.SetByCSPRNG()
	fmt.Printf("Private key : ")
	fmt.Printf("\n")
	fmt.Printf(secrKey.SerializeToHexStr())
	fmt.Printf("\n")
	fmt.Printf("Public  key : ")
	pubKey := secrKey.GetPublicKey()
	fmt.Printf(pubKey.SerializeToHexStr())
	fmt.Printf("\n")
}
