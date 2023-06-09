package signer

import (
	_ "embed"
)

//go:embed rsa_public_key
var pdPublicKey []byte
