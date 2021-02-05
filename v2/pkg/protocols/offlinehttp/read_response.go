package offlinehttp

import (
	"bufio"
	"net/http"
	"strings"
)

// readResponseFromString reads a raw http response from a string.
func readResponseFromString(data string) (*http.Response, error) {
	var final string
	if strings.HasPrefix(data, "HTTP/") {
		final = data
	} else {
		final = data[strings.LastIndex(data, "HTTP/"):] // choose last http/ in case of it being later.
	}
	return http.ReadResponse(bufio.NewReader(strings.NewReader(final)), nil)
}
