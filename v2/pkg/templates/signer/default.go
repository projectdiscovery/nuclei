package signer

var DefaultVerifier *Signer

func init() {
	DefaultVerifier, _ = NewVerifier(&Options{PublicKeyData: ecdsaPublicKey, Algorithm: ECDSA})
}
