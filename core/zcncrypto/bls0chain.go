package zcncrypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"github.com/tyler-smith/go-bip39"
	"github.com/0chain/gosdk/core/encryption"
	"github.com/herumi/bls/ffi/go/bls"
)

func init() {
	err := bls.Init(bls.CurveFp254BNb)
	if err != nil {
		panic(err)
	}
}

//BLS0ChainScheme - a signature scheme for BLS0Chain Signature
type BLS0ChainScheme struct {
	publicKey  string
	privateKey string
	mnemonic   string
}

//NewBLS0ChainScheme - create a BLS0ChainScheme object
func NewBLS0ChainScheme() *BLS0ChainScheme {
	return &BLS0ChainScheme{}
}

//GenerateKeys - implement interface
func (b0 *BLS0ChainScheme) GenerateKeys(numKeys int) (*Wallet, error) {
	// Check for recovery
	if len(b0.mnemonic) == 0 {
		entropy, err := bip39.NewEntropy(256)
		if err != nil {
			return nil, fmt.Errorf("Generating entropy failed")
		}
		b0.mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			return nil, fmt.Errorf("Generating mnemonic failed")
		}
	}
	if numKeys < 1 {
		return nil, fmt.Errorf("Invalid number of keys")
	}

	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	seed := bip39.NewSeed(b0.mnemonic, "0chain-client-split-key")
	r := bytes.NewReader(seed)
	bls.SetRandFunc(r)

	// New Wallet
	w := &Wallet{}
	w.Keys = make([]KeyPair, numKeys)
	var pk bls.PublicKey
	for i := 0; i < numKeys; i++ {
		var sk bls.SecretKey
		sk.SetByCSPRNG()
		w.Keys[i].PrivateKey = sk.SerializeToHexStr()
		pub := sk.GetPublicKey()
		w.Keys[i].PublicKey = pub.SerializeToHexStr()
		pk.Add(pub)
	}
	w.ClientKey = pk.SerializeToHexStr()
	w.ClientID = encryption.Hash(pk.Serialize())
	w.Mnemonic = b0.mnemonic
	w.Version = cryptoVersion
	w.DateCreated = time.Now().String()

	// Revert the Random function to default
	bls.SetRandFunc(nil)
	return w, nil
}

func (b0 *BLS0ChainScheme) RecoverKeys(mnemonic string, numKeys int) (*Wallet, error) {
	if mnemonic == "" {
		return nil, fmt.Errorf("Set mnemonic key failed")
	}
	if b0.publicKey != "" || b0.privateKey != "" {
		return nil, errors.New("Cannot recover when there are keys")
	}
	b0.mnemonic = mnemonic
	return b0.GenerateKeys(numKeys)
}

//SetPrivateKey - implement interface
func (b0 *BLS0ChainScheme) SetPrivateKey(privateKey string) error {
	if b0.publicKey != "" {
		return errors.New("cannot set private key when there is a public key")
	}
	if b0.privateKey != "" {
		return errors.New("private key already exists")
	}
	b0.privateKey = privateKey
	return nil
}

//SetPublicKey - implement interface
func (b0 *BLS0ChainScheme) SetPublicKey(publicKey string) error {
	if b0.privateKey != "" {
		return errors.New("cannot set public key when there is a private key")
	}
	if b0.publicKey != "" {
		return errors.New("public key already exists")
	}
	b0.publicKey = publicKey
	return nil
}

func (b0 *BLS0ChainScheme) rawSign(hash string) (*bls.Sign, error) {
	var sk bls.SecretKey
	if b0.privateKey == "" {
		return nil, errors.New("private key does not exists for signing")
	}
	rawHash, err := hex.DecodeString(hash)
	if err != nil {
		return nil, err
	}
	if rawHash == nil {
		return nil, errors.New("failed hash while signing")
	}
	sk.SetByCSPRNG()
	sk.DeserializeHexStr(b0.privateKey)
	sig := sk.Sign(string(rawHash))
	return sig, nil
}

//Sign - implement interface
func (b0 *BLS0ChainScheme) Sign(hash string) (string, error) {
	sig, err := b0.rawSign(hash)
	if err != nil {
		return "", err
	}
	return sig.SerializeToHexStr(), nil
}

//Verify - implement interface
func (b0 *BLS0ChainScheme) Verify(signature, msg string) (bool, error) {
	if b0.publicKey == "" {
		return false, errors.New("public key does not exists for verification")
	}
	var sig bls.Sign
	var pk bls.PublicKey
	err := sig.DeserializeHexStr(signature)
	if err != nil {
		return false, err
	}
	rawHash, err := hex.DecodeString(msg)
	if err != nil {
		return false, err
	}
	if rawHash == nil {
		return false, errors.New("failed hash while signing")
	}
	pk.DeserializeHexStr(b0.publicKey)
	return sig.Verify(&pk, string(rawHash)), nil
}

func (b0 *BLS0ChainScheme) Add(signature, msg string) (string, error) {
	var sign bls.Sign
	err := sign.DeserializeHexStr(signature)
	if err != nil {
		return "", err
	}
	signature1, err := b0.rawSign(msg)
	if err != nil {
		return "", fmt.Errorf("BLS signing failed - %s", err.Error())
	}
	sign.Add(signature1)
	return sign.SerializeToHexStr(), nil
}