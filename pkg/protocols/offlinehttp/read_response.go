package offlinehttp

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// noMinor matches a leading status-line protocol with no minor version, such
// as "HTTP/2 ". The go parser only accepts HTTP/X.Y.
var noMinor = regexp.MustCompile(`^HTTP/[0-9] `)

// errNotRequest marks data that does not start with an HTTP request, so the
// caller parses it as a bare response instead.
var errNotRequest = errors.New("not an http request")

// readResponseFromString reads one raw HTTP response. Data may be the response
// itself or a request followed by that response. A status line is recognized
// only where a response starts, never by searching the body for "HTTP/".
func readResponseFromString(data string) (*http.Response, error) {
	resp, err := readRequestResponse(data)
	if err == nil || !errors.Is(err, errNotRequest) {
		return resp, err
	}
	return readResponse(data, nil)
}

// readRequestResponse reads a raw HTTP request from the start of data and the
// response that follows it.
func readRequestResponse(data string) (*http.Response, error) {
	sr := strings.NewReader(data)
	br := bufio.NewReader(sr)
	// unread bytes are either still in sr or buffered in br
	unread := func() string { return data[len(data)-sr.Len()-br.Buffered():] }

	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, errNotRequest
	}
	afterHeaders := unread()
	// the response follows the request body, so it has to be read first.
	// a dump that keeps Content-Length but drops the body is tried at the headers.
	if _, err := io.Copy(io.Discard, req.Body); err == nil {
		if resp, err := readResponse(unread(), req); err == nil {
			return resp, nil
		}
	}
	return readResponse(afterHeaders, req)
}

// maxInterimResponses bounds how many interim responses are skipped before the
// final one. Each skip copies the remainder of data.
const maxInterimResponses = 5

// readResponse reads a raw HTTP response whose status line starts data, after
// any leading blank lines. Interim responses such as 100 Continue are skipped,
// as the HTTP client does. The last interim response is returned when no final
// response follows it.
func readResponse(data string, req *http.Request) (*http.Response, error) {
	var lastInterim *http.Response
	for range maxInterimResponses + 1 {
		data = strings.TrimLeft(data, "\r\n")
		data = addMinorVersionToHTTP(data)
		sr := strings.NewReader(data)
		br := bufio.NewReader(sr)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			if lastInterim != nil {
				return lastInterim, nil
			}
			return nil, err
		}
		if !isInterimResponse(resp) {
			return resp, nil
		}
		if lastInterim != nil && lastInterim.Body != nil {
			_ = lastInterim.Body.Close()
		}
		lastInterim = resp
		data = data[len(data)-sr.Len()-br.Buffered():]
	}
	return lastInterim, nil
}

// isInterimResponse reports whether resp is an interim response, such as
// 100 Continue, that comes before the final response. 101 Switching Protocols
// is the response.
func isInterimResponse(resp *http.Response) bool {
	return resp != nil && resp.StatusCode >= 100 && resp.StatusCode <= 199 && resp.StatusCode != http.StatusSwitchingProtocols
}

// addMinorVersionToHTTP inserts ".0" into a leading protocol such as HTTP/2.
// Only those bytes change, so the reason phrase, headers, and body stay intact.
func addMinorVersionToHTTP(data string) string {
	if !noMinor.MatchString(data) {
		return data
	}
	const protoLen = len("HTTP/X")
	return data[:protoLen] + ".0" + data[protoLen:]
}
