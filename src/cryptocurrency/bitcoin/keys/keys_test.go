package keys

import (
	"testing"
	"crypto/ecdsa"
	"fmt"
)

func TestKeyGeneration(t *testing.T) {

	privateKey := generateKeyPair()

	var publicKey ecdsa.PublicKey
	publicKey = privateKey.PublicKey

	fmt.Println("Private Key :")
	fmt.Printf("%x \n", privateKey)

	fmt.Println("Public Key :")
	fmt.Printf("%x \n", publicKey)

	t.Log("FIN\n")
}

