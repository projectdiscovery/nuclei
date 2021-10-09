package offlinehttp

import (
	"bufio"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

var noMinor = regexp.MustCompile(`HTTP\/([0-9]) `)

// readResponseFromString reads a raw http response from a string.
func readResponseFromString(data string) (*http.Response, error) {
	var final string

	if strings.HasPrefix(data, "HTTP/") {
		final = addMinorVersionToHTTP(data)
	} else {
		lastIndex := strings.LastIndex(data, "HTTP/")
		if lastIndex == -1 {
			return nil, errors.New("malformed raw http response")
		}
		final = data[lastIndex:] // choose last http/ in case of it being later.

		final = addMinorVersionToHTTP(final)
	}
	return http.ReadResponse(bufio.NewReader(strings.NewReader(final)), nil)
}

// addMinorVersionToHTTP tries to add a minor version to http status header
// fixing the compatibility issue with go standard library.
func addMinorVersionToHTTP(data string) string {
	matches := noMinor.FindAllStringSubmatch(data, 1)
	if len(matches) == 0 {
		return data
	}
	if len(matches[0]) < 2 {
		return data
	}
	replacedVersion := strings.Replace(matches[0][0], matches[0][1], matches[0][1]+".0", 1)
	data = strings.Replace(data, matches[0][0], replacedVersion, 1)
	return data
}
