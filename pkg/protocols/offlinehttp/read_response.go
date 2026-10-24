package offlinehttp

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var noMinor = regexp.MustCompile(`^HTTP/[0-9] `)

// readResponseFromString reads a raw http response from a string.
func readResponseFromString(data string) (*http.Response, error) {
	// Check if "data" contains RFC compatible Request followed by a response
	reqResp, reqErr := readRequestResponse(data)
	if reqErr == nil && !isInterimResponse(reqResp) {
		return reqResp, nil
	}

	// otherwise tries to find where the response starts. After an interim
	// response, the final response answers the same request.
	var req *http.Request
	if reqErr == nil {
		req = reqResp.Request
	}
	resp, err := readFallbackResponse(data, req)
	foundFinal := err == nil && !isInterimResponse(resp)
	if reqErr != nil || foundFinal {
		return resp, err
	}
	// keep the interim response found after the request when no final one is found
	return reqResp, nil
}

// readRequestResponse reads a raw http request from the start of data and the
// response that follows it.
func readRequestResponse(data string) (*http.Response, error) {
	sr := strings.NewReader(data)
	br := bufio.NewReader(sr)
	// unread bytes are either still in sr or buffered in br
	unread := func() string { return data[len(data)-sr.Len()-br.Buffered():] }

	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, err
	}
	afterHeaders := unread()
	// the response follows the request body, so it has to be read first
	if _, err := io.Copy(io.Discard, req.Body); err == nil {
		if resp, err := readResponse(unread(), req); err == nil {
			return resp, nil
		}
	}
	// some dumps keep the request's Content-Length but leave out its body
	return readResponse(afterHeaders, req)
}

// readFallbackResponse reads the response at the start of data or, when data
// starts with something else, at the last "HTTP/" in it.
func readFallbackResponse(data string, req *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(data, "HTTP/") {
		lastIndex := strings.LastIndex(data, "HTTP/")
		if lastIndex == -1 {
			return nil, errors.New("malformed raw http response")
		}
		data = data[lastIndex:] // choose last http/ in case of it being later.
	}
	return readResponse(data, req)
}

// maxInterimResponses bounds the interim responses skipped before the final
// one, since reading each of them copies the rest of data.
const maxInterimResponses = 5

// readResponse reads a raw http response whose status line starts data,
// skipping interim responses such as 100 Continue as the http client does.
// The last interim response is returned when no final response follows it.
func readResponse(data string, req *http.Request) (*http.Response, error) {
	var lastInterim *http.Response
	for range maxInterimResponses + 1 {
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
		lastInterim = resp
		// unread bytes are either still in sr or buffered in br. Some dumps
		// put blank lines between an interim response and the next one.
		data = strings.TrimLeft(data[len(data)-sr.Len()-br.Buffered():], "\r\n")
	}
	return lastInterim, nil
}

// isInterimResponse reports whether resp is an interim response, such as
// 100 Continue, that comes before the final response.
func isInterimResponse(resp *http.Response) bool {
	return resp.StatusCode >= 100 && resp.StatusCode <= 199 && resp.StatusCode != http.StatusSwitchingProtocols
}

// addMinorVersionToHTTP adds a minor version to a status line protocol such as
// HTTP/2, because the go standard library only parses HTTP/X.Y. Only the leading
// protocol is changed so the reason phrase, headers, and body stay intact.
func addMinorVersionToHTTP(data string) string {
	if !noMinor.MatchString(data) {
		return data
	}
	const protoLen = len("HTTP/X")
	return data[:protoLen] + ".0" + data[protoLen:]
}
