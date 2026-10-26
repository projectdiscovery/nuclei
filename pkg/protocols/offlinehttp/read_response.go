package offlinehttp

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var (
	noMinor             = regexp.MustCompile(`^HTTP/([0-9]) `)
	responseStatusRegex = regexp.MustCompile(`(?m)^HTTP/[0-9](?:\.[0-9])?\s+[0-9]{3}`)
)

// readResponseFromString reads a raw http response from a string.
func readResponseFromString(data string) (*http.Response, error) {
	// Check if "data" contains RFC compatible Request followed by a response
	br := bufio.NewReader(strings.NewReader(data))
	if req, err := http.ReadRequest(br); err == nil {
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
		}
		remaining, _ := io.ReadAll(br)
		if len(remaining) > 0 {
			remainingStr := addMinorVersionToHTTP(string(remaining))
			if resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(remainingStr)), req); err == nil {
				return resp, nil
			}
		}
	}

	// otherwise tries to patch known cases such as http minor version
	var final string
	if strings.HasPrefix(data, "HTTP/") {
		final = addMinorVersionToHTTP(data)
	} else {
		loc := responseStatusRegex.FindStringIndex(data)
		if loc == nil {
			return nil, errors.New("malformed raw http response")
		}
		final = addMinorVersionToHTTP(data[loc[0]:])
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
