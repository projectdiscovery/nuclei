package offlinehttp

import (
	"bufio"
	"errors"
	"net/http"
	"strings"
)

// readResponseFromString reads a raw http response from a string.
func readResponseFromString(data string) (*http.Response, error) {
	var final string
	if strings.HasPrefix(data, "HTTP/") {
		final = data
	} else {
		lastIndex := strings.LastIndex(data, "HTTP/")
		if lastIndex == -1 {
			return nil, errors.New("malformed raw http response")
		}
		final = data[lastIndex:] // choose last http/ in case of it being later.
	}
	return http.ReadResponse(bufio.NewReader(strings.NewReader(final)), nil)
}
