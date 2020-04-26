package executor

import (
	"net/http"
	"strings"
	"unsafe"
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
