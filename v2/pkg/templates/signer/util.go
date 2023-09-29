package signer

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// SignableTemplate is a template that can be signed
type SignableTemplate interface {
	// GetFileImports returns a list of files that are imported by the template
	GetFileImports() []string
}

const (
	SignaturePattern = "# digest: "
	SignatureFmt     = SignaturePattern + "%x"
)

func RemoveSignatureFromData(data []byte) []byte {
	return bytes.Trim(ReDigest.ReplaceAll(data, []byte("")), "\n")
}

func Sign(sign *Signer, data []byte, tmpl SignableTemplate) (string, error) {
	if sign == nil {
		return "", errors.New("invalid nil signer")
	}
	buff := bytes.NewBuffer(RemoveSignatureFromData(data))
	// if file has any imports process them
	for _, file := range tmpl.GetFileImports() {
		bin, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		buff.WriteRune('\n')
		buff.Write(bin)
	}
	signatureData, err := sign.Sign(buff.Bytes())
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(SignatureFmt, signatureData), nil
}

// Verify verifies the signature of the data
func Verify(sign *Signer, data []byte, tmpl SignableTemplate) (bool, error) {
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

	buff := bytes.NewBuffer(RemoveSignatureFromData(data))
	// if file has any imports process them
	for _, file := range tmpl.GetFileImports() {
		bin, err := os.ReadFile(file)
		if err != nil {
			return false, err
		}
		buff.WriteRune('\n')
		buff.Write(bin)
	}

	return sign.Verify(buff.Bytes(), digest)
}
