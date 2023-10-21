package encoding

import (
	"encoding/base64"
	"regexp"
)

// Base64 is a base64 encoder
type Base64 struct{}

var (
	_           Encoder = &Base64{}
	base64Regex         = regexp.MustCompile(`^[A-Za-z0-9+/_-]+={0,2}$`)
)

// NewBase64 returns a new base64 encoder
func NewBase64() *Base64 {
	return &Base64{}
}

// IsType returns true if the data is base64 encoded
func (b *Base64) IsType(data string) bool {
	regexMatch := base64Regex.MatchString(data)
	divisibleBy4 := len(data)%4 == 0

	return regexMatch && divisibleBy4
}

// Encode encodes the data into base64 format
func (b *Base64) Encode(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

// Decode decodes the data from base64 format
func (b *Base64) Decode(data string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	return string(decoded), err
}

// Name returns the name of the encoder
func (b *Base64) Name() string {
	return "base64"
}
