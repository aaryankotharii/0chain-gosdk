package BN254

import (
	"encoding/hex"
	"fmt"
	"github.com/0chain/gosdk/core/zcncrypto"
	"github.com/0chain/gosdk/core/zcncrypto/miracl/core"
	herumi "github.com/herumi/bls-go-binary/bls"
	"github.com/stretchr/testify/assert"
	"github.com/tyler-smith/go-bip39"
	"testing"
)

func SecretKeyToStr(sec *herumi.SecretKey) string {
	s := herumi.CastFromSecretKey(sec).GetString(16)
	return fmt.Sprintf("%064s", s)
}

func G1ToStr(P *herumi.G1) string {
	herumi.G1Normalize(P, P)
	return fmt.Sprintf("(%064s,%064s)", P.X.GetString(16), P.Y.GetString(16))
}

func SignToStr(sig *herumi.Sign) string {
	P := herumi.CastFromSign(sig)
	return G1ToStr(P)
}

func TestKeyGeneration(t *testing.T) {
	res := Init()
	assert.True(t, res == 0)

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

	const BGS = int(MODBYTES)
	const BFS = int(MODBYTES)
	const G1S = BFS + 1   /* Group 1 Size */
	const G2S = 2*BFS + 1 /* Group 2 Size */

	var S [BGS]byte
	var W [G2S]byte

	res = KeyPairGenerate(seed, S[:], W[:])
	if res != 0 {
		fmt.Printf("Failed to generate keys\n")
		return
	}
	fmt.Printf("Private key : ")
	privateKey := hex.EncodeToString(S[:])
	fmt.Printf(privateKey)
	fmt.Printf("\n")
	fmt.Printf("Public  key : ")
	publicKey := hex.EncodeToString(W[:])
	fmt.Printf(publicKey)
	fmt.Printf("\n")

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

	// verify
	var SIG [G1S]byte
	mess := "This is a test message"
	Core_Sign(SIG[:], []byte(mess), S[:])
	res = Core_Verify(SIG[:], []byte(mess), W[:])
	assert.Equal(t, res, 0, "Signature is *NOT* OK\n")

}

func TestMainHerumi(t *testing.T) {
	if herumi.Init(herumi.CurveFp254BNb) != nil {
		t.Fatal("herumi.Init")
	}
	if Init() == BLS_FAIL {
		fmt.Printf("err")
		return
	}
	// initialize at once
	H := NewHashAndMap()

	var oneSec herumi.SecretKey
	oneSec.SetHexString("1")
	var P2, Q2 herumi.G1

	const N = 1000
	for i := 0; i < N; i++ {
		key := fmt.Sprintf("sec%v\n", i)
		hash := core.NewHASH256()
		hash.Process_array([]byte(key))
		md := hash.Hash()

		var sec2 herumi.SecretKey

		// check secret key
		sec1 := H.copyAndMask(md)
		sec2.SetLittleEndian(md)

		str1 := sec1.ToString()
		str2 := SecretKeyToStr(&sec2)
		if str1 != str2 {
			t.Errorf("bad str i=%v\ns1=%v\ns2=%v\n", i, str1, str2)
		}

		msg := []byte(fmt.Sprintf("msg%v\n", i))

		// check hash-and-map function
		P1 := H.SetHashOf(msg)
		P2.HashAndMapTo(msg)

		str1 = P1.ToString()
		str2 = G1ToStr(&P2)
		if str1 != str2 {
			t.Errorf("bad map i=%v\nsig1=%s\nsig2=%s\n", i, str1, str2)
		}

		// check mul
		Q1 := P1.Mul(sec1)
		herumi.G1Mul(&Q2, &P2, herumi.CastFromSecretKey(&sec2))

		str1 = Q1.ToString()
		str2 = G1ToStr(&Q2)
		if str1 != str2 {
			t.Errorf("bad sig i=%v s=%s\nP=%s\nsig1=%s\nsig2=%s\n", i, sec1.ToString(), P1.ToString(), str1, str2)
		}
	}

	for i := 0; i < N; i++ {
		x := NewFPint(i)
		r := H.sq.Get(x)
		if r != nil {
			r.sqr()
			if !r.Equals(x) {
				fmt.Printf("err")
			}
		}
	}
}
