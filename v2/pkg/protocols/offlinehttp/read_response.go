package offlinehttp

import (
	"bufio"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

// readResponseFromString reads a raw http response from a string.
func readResponseFromString(data string) (*http.Response, error) {
	var final string
	noMinor := regexp.MustCompile(`HTTP\/[0-9] `)

	if strings.HasPrefix(data, "HTTP/") {
		// Go could not parse http version with no minor version
		if noMinor.MatchString(data) {
			// add minor version
			data = strings.Replace(data, "HTTP/2", "HTTP/2.0", 1)
			data = strings.Replace(data, "HTTP/3", "HTTP/3.0", 1)
		}
		final = data
	} else {
		lastIndex := strings.LastIndex(data, "HTTP/")
		if lastIndex == -1 {
			return nil, errors.New("malformed raw http response")
		}
		final = data[lastIndex:] // choose last http/ in case of it being later.

		if noMinor.MatchString(final) {
			final = strings.ReplaceAll(final, "HTTP/2", "HTTP/2.0")
			final = strings.ReplaceAll(final, "HTTP/3", "HTTP/3.0")
		}
	}
	return http.ReadResponse(bufio.NewReader(strings.NewReader(final)), nil)
}
