package signer

import (
	_ "embed"
)

//go:embed ecdsa_public_key.pem
var ecdsaPublicKey []byte
