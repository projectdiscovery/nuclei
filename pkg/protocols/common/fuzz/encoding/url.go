package encoding

import (
	"net/url"
	"regexp"
)

// URL is a url encoder
type URL struct{}

var (
	_               Encoder = &URL{}
	urlEncodedRegex         = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
)

// NewURL returns a new URL encoder
func NewURL() *URL {
	return &URL{}
}

// IsType returns true if the data is url encoded
func (u *URL) IsType(data string) bool {
	return urlEncodedRegex.MatchString(data)
}

// Encode encodes the data into url encoded format
func (u *URL) Encode(data string) string {
	return url.QueryEscape(data)
}

// Decode decodes the data from url encoded format
func (u *URL) Decode(data string) (string, error) {
	return url.QueryUnescape(data)
}

// Name returns the name of the encoder
func (u *URL) Name() string {
	return "url"
}
