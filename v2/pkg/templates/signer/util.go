package signer

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	SignaturePattern = "# digest: "
	SignatureFmt     = SignaturePattern + "%x"
)

func RemoveSignatureFromData(data []byte) []byte {
	return bytes.Trim(ReDigest.ReplaceAll(data, []byte("")), "\n")
}

func Sign(sign *Signer, data []byte) (string, error) {
	if sign == nil {
		return "", errors.New("invalid nil signer")
	}
	cleanedData := RemoveSignatureFromData(data)
	signatureData, err := sign.Sign(cleanedData)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(SignatureFmt, signatureData), nil
}

func Verify(sign *Signer, data []byte) (bool, error) {
	if sign == nil {
		return false, errors.New("invalid nil verifier")
	}
	digestData := ReDigest.Find(data)
	if len(digestData) == 0 {
		return false, errors.New("digest not found")
	}

	digestData = bytes.TrimSpace(bytes.TrimPrefix(digestData, []byte(SignaturePattern)))
	digest, err := hex.DecodeString(string(digestData))
	if err != nil {
		return false, err
	}

	cleanedData := RemoveSignatureFromData(data)

	return sign.Verify(cleanedData, digest)
}
