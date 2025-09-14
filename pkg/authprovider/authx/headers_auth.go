package authx

import (
	"net/http"

	"github.com/projectdiscovery/retryablehttp-go"
)

var (
	_ AuthStrategy = &HeadersAuthStrategy{}
)

// HeadersAuthStrategy is a strategy for headers auth
type HeadersAuthStrategy struct {
	Data *Secret
}

// NewHeadersAuthStrategy creates a new headers auth strategy
func NewHeadersAuthStrategy(data *Secret) *HeadersAuthStrategy {
	return &HeadersAuthStrategy{Data: data}
}

// Apply applies the headers auth strategy to the request
func (s *HeadersAuthStrategy) Apply(req *http.Request) {
	for _, header := range s.Data.Headers {
		req.Header[nonCanonicalMIMEHeaderKey(header.Key)] = []string{header.Value}
	}
}

// ApplyOnRR applies the headers auth strategy to the retryable request
func (s *HeadersAuthStrategy) ApplyOnRR(req *retryablehttp.Request) {
	for _, header := range s.Data.Headers {
		req.Header[nonCanonicalMIMEHeaderKey(header.Key)] = []string{header.Value}
	}
}

func nonCanonicalMIMEHeaderKey(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if validHeaderFieldByte(c) {
			return s
		}
	}
	return s
}

func validHeaderFieldByte(c byte) bool {
	const mask = 0 |
		(1<<(10)-1)<<'0' |
		(1<<(26)-1)<<'a' |
		(1<<(26)-1)<<'A' |
		1<<'!' |
		1<<'#' |
		1<<'$' |
		1<<'%' |
		1<<'&' |
		1<<'\'' |
		1<<'*' |
		1<<'+' |
		1<<'-' |
		1<<'.' |
		1<<'^' |
		1<<'_' |
		1<<'`' |
		1<<'|' |
		1<<'~'
	return ((uint64(1)<<c)&(mask&(1<<64-1)) |
		(uint64(1)<<(c-64))&(mask>>64)) != 0
}
