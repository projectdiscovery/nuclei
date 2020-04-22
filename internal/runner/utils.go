package runner

import (
	"net/http"
	"net/url"
	"strings"
	"unsafe"

	"github.com/asaskevich/govalidator"
)

// unsafeToString converts byte slice to string with zero allocations
func unsafeToString(bs []byte) string {
	return *(*string)(unsafe.Pointer(&bs))
}

// headersToString converts http headers to string
func headersToString(headers http.Header) string {
	builder := &strings.Builder{}

	for header, values := range headers {
		builder.WriteString(header)
		builder.WriteString(": ")

		for i, value := range values {
			builder.WriteString(value)
			if i != len(values)-1 {
				builder.WriteRune(',')
			}
		}
		builder.WriteRune('\n')
	}
	return builder.String()
}

// isURL tests a string to determine if it is a well-structured url or not.
func isURL(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}

	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

// isDNS tests a string to determine if it is a well-structured dns or not
// even if it's oneliner, we leave it wrapped in a function call for
// future improvements
func isDNS(toTest string) bool {
	return govalidator.IsDNSName(toTest)
}
