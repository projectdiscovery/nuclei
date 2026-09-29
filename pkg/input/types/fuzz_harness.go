package types

import (
	"fmt"
	"strings"
)

const (
	fuzzMaxInputSize  = 16 << 10
	fuzzMaxHeaders    = 8
	fuzzMaxValueBytes = 256
)

var (
	fuzzMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
	fuzzPaths   = []string{"/", "/api/v1/users", "/login", "/search?q=nuclei", "?debug=true"}
	fuzzHosts   = []string{"example.com", "scanme.sh", "127.0.0.1", "example.com:8080"}
)

type fuzzHeader struct {
	key   string
	value string
}

type fuzzRawRequestCandidate struct {
	method    string
	path      string
	host      string
	targetURL string
	headers   []fuzzHeader
	body      string
}

func fuzzRawRequestParsing(data []byte) bool {
	raw, targetURL, ok := rawRequestFromFuzzData(data)
	if !ok {
		return false
	}

	parsed := false
	if rr, err := ParseRawRequest(raw); err == nil {
		exerciseFuzzRequestResponse(rr)
		parsed = true
	}
	if rr, err := ParseRawRequestWithURL(raw, targetURL); err == nil {
		exerciseFuzzRequestResponse(rr)
		parsed = true
	}
	if rr, err := ParseRawRequest(string(data)); err == nil {
		exerciseFuzzRequestResponse(rr)
		parsed = true
	}
	if rr, err := ParseRawRequestWithURL(string(data), targetURL); err == nil {
		exerciseFuzzRequestResponse(rr)
		parsed = true
	}

	return parsed
}

func rawRequestFromFuzzData(data []byte) (string, string, bool) {
	if len(data) == 0 || len(data) > fuzzMaxInputSize {
		return "", "", false
	}

	candidate := newFuzzRawRequestCandidate(data)
	candidate.applyLines(splitFuzzLines(data))
	return candidate.build(), candidate.targetURL, true
}

func newFuzzRawRequestCandidate(data []byte) *fuzzRawRequestCandidate {
	method := fuzzMethods[int(fuzzByteAt(data, 0))%len(fuzzMethods)]
	path := fuzzPaths[int(fuzzByteAt(data, 1))%len(fuzzPaths)]
	host := fuzzHosts[int(fuzzByteAt(data, 2))%len(fuzzHosts)]

	return &fuzzRawRequestCandidate{
		method:    method,
		path:      path,
		host:      host,
		targetURL: "https://" + host + path,
		headers: []fuzzHeader{
			{key: "User-Agent", value: "nuclei-fuzz"},
		},
		body: fuzzBody(string(data)),
	}
}

func (candidate *fuzzRawRequestCandidate) applyLines(lines []string) {
	for _, line := range lines {
		key, value, ok := cutFuzzKV(line)
		if !ok {
			candidate.body = fuzzBody(line)
			continue
		}

		switch key {
		case "method":
			candidate.method = fuzzMethod(value, candidate.method)
		case "path":
			candidate.path = fuzzRelativePath(value, candidate.path)
		case "host":
			candidate.host = fuzzHost(value, candidate.host)
		case "url", "target-url":
			candidate.targetURL = fuzzAbsoluteURL(value, candidate.targetURL)
		case "header":
			candidate.addHeader(value)
		case "body":
			candidate.body = fuzzBody(value)
		}
	}
}

func (candidate *fuzzRawRequestCandidate) addHeader(value string) {
	key, headerValue, ok := strings.Cut(value, ":")
	if !ok {
		key, headerValue, ok = strings.Cut(value, "=")
	}
	if !ok {
		return
	}

	key = fuzzHeaderKey(key)
	if key == "" || strings.EqualFold(key, "Host") || len(candidate.headers) >= fuzzMaxHeaders {
		return
	}
	candidate.headers = append(candidate.headers, fuzzHeader{key: key, value: fuzzHeaderValue(headerValue)})
}

func (candidate *fuzzRawRequestCandidate) build() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s %s HTTP/1.1\r\n", candidate.method, candidate.path)
	fmt.Fprintf(&builder, "Host: %s\r\n", candidate.host)
	for _, header := range candidate.headers {
		fmt.Fprintf(&builder, "%s: %s\r\n", header.key, header.value)
	}
	builder.WriteString("\r\n")
	builder.WriteString(candidate.body)
	return builder.String()
}

func exerciseFuzzRequestResponse(rr *RequestResponse) {
	if rr == nil {
		panic("nil request response")
	}
	if rr.Request == nil {
		panic("nil parsed request")
	}
	_ = rr.Clone()
	_ = rr.ID()
	_, _ = rr.MarshalJSON()
}

func splitFuzzLines(data []byte) []string {
	fields := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == '\n' || r == '\r' || r == ';'
	})
	if len(fields) > fuzzMaxHeaders*4 {
		fields = fields[:fuzzMaxHeaders*4]
	}

	lines := make([]string, 0, len(fields))
	for _, field := range fields {
		field = fuzzTrim(field)
		if field != "" {
			lines = append(lines, field)
		}
	}
	return lines
}

func cutFuzzKV(line string) (string, string, bool) {
	key, value, ok := strings.Cut(line, "=")
	if !ok {
		key, value, ok = strings.Cut(line, ":")
	}
	if !ok {
		return "", "", false
	}
	return strings.ToLower(fuzzTrim(key)), fuzzTrim(value), true
}

func fuzzByteAt(data []byte, index int) byte {
	if len(data) == 0 {
		return 0
	}
	return data[index%len(data)]
}

func fuzzMethod(value, fallback string) string {
	value = strings.ToUpper(fuzzToken(value, 16))
	if value == "" {
		return fallback
	}
	return value
}

func fuzzRelativePath(value, fallback string) string {
	value = fuzzTrim(value)
	if value == "" {
		return fallback
	}
	if len(value) > fuzzMaxValueBytes {
		value = value[:fuzzMaxValueBytes]
	}
	if strings.HasPrefix(value, "?") || strings.HasPrefix(value, "/") {
		return value
	}
	return "/" + value
}

func fuzzAbsoluteURL(value, fallback string) string {
	value = fuzzTrim(value)
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return value
	}
	host := fuzzHost(value, "")
	if host == "" {
		return fallback
	}
	return "https://" + host + "/"
}

func fuzzHost(value, fallback string) string {
	value = strings.ToLower(fuzzTrim(value))
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '.' || r == '-' || r == ':':
			builder.WriteRune(r)
		}
		if builder.Len() >= 128 {
			break
		}
	}
	if builder.Len() == 0 {
		return fallback
	}
	return builder.String()
}

func fuzzHeaderKey(value string) string {
	return fuzzToken(value, 64)
}

func fuzzHeaderValue(value string) string {
	return fuzzTrim(value)
}

func fuzzBody(value string) string {
	value = strings.ReplaceAll(value, "\x00", "")
	if len(value) > fuzzMaxValueBytes {
		value = value[:fuzzMaxValueBytes]
	}
	return value
}

func fuzzToken(value string, limit int) string {
	value = fuzzTrim(value)
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r - 'a' + 'A')
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-':
			builder.WriteRune(r)
		}
		if builder.Len() >= limit {
			break
		}
	}
	return builder.String()
}

func fuzzTrim(value string) string {
	value = strings.TrimSpace(strings.NewReplacer("\x00", "", "\r", " ", "\n", " ").Replace(value))
	if len(value) > fuzzMaxValueBytes {
		value = value[:fuzzMaxValueBytes]
	}
	return value
}
