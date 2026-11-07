package raw

import (
	"fmt"
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"
)

const (
	fuzzMaxInputSize  = 16 << 10
	fuzzMaxHeaders    = 8
	fuzzMaxValueBytes = 256
)

var (
	fuzzRawMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
	fuzzRawPaths   = []string{"/", "", "/admin/login", "/api/v1/users?id=1", "1337?with=param", "http://127.0.0.1/foo?id=1"}
	fuzzRawHosts   = []string{"example.com", "{{Hostname}}", "127.0.0.1", "example.com:8080"}
	fuzzInputURLs  = []string{"https://example.com", "https://example.com/base", "http://target.local:8080/root?x=1", "http://httpbin.org/bar"}
)

type fuzzRawHeader struct {
	key   string
	value string
}

type fuzzRawHTTPCandidate struct {
	method               string
	path                 string
	host                 string
	inputURL             string
	unsafe               bool
	disablePathAutomerge bool
	headers              []fuzzRawHeader
	body                 string
}

func fuzzRawHTTPParsing(data []byte) bool {
	rawRequest, inputURL, unsafe, disablePathAutomerge, ok := rawHTTPRequestFromFuzzData(data)
	if !ok {
		return false
	}

	parsedURL, err := urlutil.Parse(inputURL)
	if err != nil {
		return false
	}

	parsed := false
	for _, unsafeMode := range fuzzBoolCases(unsafe) {
		for _, disableAutomerge := range fuzzBoolCases(disablePathAutomerge) {
			request, parseErr := Parse(rawRequest, parsedURL.Clone(), unsafeMode, disableAutomerge)
			if parseErr == nil {
				exerciseFuzzRawRequest(request)
				parsed = true
			}
		}

		request, parseErr := ParseRawRequest(rawRequest, unsafeMode)
		if parseErr == nil {
			exerciseFuzzRawRequest(request)
			parsed = true
		}
	}

	if looksLikeRawHTTPRequest(data) {
		rawInput := string(data)
		for _, unsafeMode := range []bool{false, true} {
			request, parseErr := Parse(rawInput, parsedURL.Clone(), unsafeMode, disablePathAutomerge)
			if parseErr == nil {
				exerciseFuzzRawRequest(request)
				parsed = true
			}

			request, parseErr = ParseRawRequest(rawInput, unsafeMode)
			if parseErr == nil {
				exerciseFuzzRawRequest(request)
				parsed = true
			}
		}
	}

	return parsed
}

func rawHTTPRequestFromFuzzData(data []byte) (string, string, bool, bool, bool) {
	if len(data) == 0 || len(data) > fuzzMaxInputSize {
		return "", "", false, false, false
	}

	candidate := newFuzzRawHTTPCandidate(data)
	candidate.applyLines(splitFuzzLines(data))
	return candidate.build(), candidate.inputURL, candidate.unsafe, candidate.disablePathAutomerge, true
}

func newFuzzRawHTTPCandidate(data []byte) *fuzzRawHTTPCandidate {
	flags := fuzzByteAt(data, 1)
	return &fuzzRawHTTPCandidate{
		method:               fuzzRawMethods[int(fuzzByteAt(data, 0))%len(fuzzRawMethods)],
		path:                 fuzzRawPaths[int(fuzzByteAt(data, 2))%len(fuzzRawPaths)],
		host:                 fuzzRawHosts[int(fuzzByteAt(data, 3))%len(fuzzRawHosts)],
		inputURL:             fuzzInputURLs[int(fuzzByteAt(data, 4))%len(fuzzInputURLs)],
		unsafe:               flags&0x01 != 0,
		disablePathAutomerge: flags&0x02 != 0,
		headers: []fuzzRawHeader{
			{key: "User-Agent", value: "nuclei-fuzz"},
		},
		body: fuzzRawBody(string(data)),
	}
}

func (candidate *fuzzRawHTTPCandidate) applyLines(lines []string) {
	for _, line := range lines {
		key, value, ok := cutFuzzKV(line)
		if !ok {
			candidate.body = fuzzRawBody(line)
			continue
		}

		switch key {
		case "method":
			candidate.method = fuzzRawMethod(value, candidate.method)
		case "path":
			if value == "" {
				candidate.path = ""
			} else {
				candidate.path = fuzzRawPath(value, candidate.path)
			}
		case "host":
			candidate.host = fuzzRawHost(value, candidate.host)
		case "input-url", "url":
			candidate.inputURL = fuzzRawInputURL(value, candidate.inputURL)
		case "unsafe":
			candidate.unsafe = fuzzRawBool(value, candidate.unsafe)
		case "disable-automerge", "disable-path-automerge":
			candidate.disablePathAutomerge = fuzzRawBool(value, candidate.disablePathAutomerge)
		case "header":
			candidate.addHeader(value)
		case "body":
			candidate.body = fuzzRawBody(value)
		}
	}
}

func (candidate *fuzzRawHTTPCandidate) addHeader(value string) {
	key, headerValue, ok := strings.Cut(value, ":")
	if !ok {
		key, headerValue, ok = strings.Cut(value, "=")
	}
	if !ok {
		return
	}

	key = fuzzRawHeaderKey(key)
	if key == "" || strings.EqualFold(key, "Host") || len(candidate.headers) >= fuzzMaxHeaders {
		return
	}
	candidate.headers = append(candidate.headers, fuzzRawHeader{key: key, value: fuzzRawHeaderValue(headerValue)})
}

func (candidate *fuzzRawHTTPCandidate) build() string {
	var builder strings.Builder
	if candidate.path == "" {
		fmt.Fprintf(&builder, "%s HTTP/1.1\r\n", candidate.method)
	} else {
		fmt.Fprintf(&builder, "%s %s HTTP/1.1\r\n", candidate.method, candidate.path)
	}
	fmt.Fprintf(&builder, "Host: %s\r\n", candidate.host)
	for _, header := range candidate.headers {
		fmt.Fprintf(&builder, "%s: %s\r\n", header.key, header.value)
	}
	builder.WriteString("\r\n")
	builder.WriteString(candidate.body)
	return builder.String()
}

func exerciseFuzzRawRequest(request *Request) {
	if request == nil {
		panic("nil raw request")
	}
	_ = request.FullURL
	_ = request.Method
	_ = request.Path
	_ = request.Data
	if len(request.UnsafeRawBytes) > 0 {
		_ = request.TryFillCustomHeaders([]string{"X-Fuzz: 1"})
	}
}

func looksLikeRawHTTPRequest(data []byte) bool {
	line := string(data)
	if index := strings.IndexAny(line, "\r\n"); index >= 0 {
		line = line[:index]
	}
	parts := strings.Fields(line)
	return len(parts) >= 3 && strings.HasPrefix(parts[2], "HTTP/")
}

func fuzzBoolCases(value bool) []bool {
	if value {
		return []bool{true, false}
	}
	return []bool{false, true}
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

func fuzzRawMethod(value, fallback string) string {
	value = strings.ToUpper(fuzzRawToken(value, 16))
	if value == "" {
		return fallback
	}
	return value
}

func fuzzRawPath(value, fallback string) string {
	value = fuzzTrim(value)
	if value == "" {
		return fallback
	}
	if len(value) > fuzzMaxValueBytes {
		value = value[:fuzzMaxValueBytes]
	}
	return value
}

func fuzzRawInputURL(value, fallback string) string {
	value = fuzzTrim(value)
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return value
	}
	host := fuzzRawHost(value, "")
	if host == "" {
		return fallback
	}
	return "https://" + host + "/"
}

func fuzzRawHost(value, fallback string) string {
	value = strings.TrimSpace(strings.NewReplacer("\x00", "", "\r", "", "\n", "", "/", "", "\\", "").Replace(value))
	if value == "{{Hostname}}" || value == "{{BaseURL}}" {
		return value
	}

	value = strings.ToLower(value)
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

func fuzzRawHeaderKey(value string) string {
	return fuzzRawToken(value, 64)
}

func fuzzRawHeaderValue(value string) string {
	return fuzzTrim(value)
}

func fuzzRawBody(value string) string {
	value = strings.ReplaceAll(value, "\x00", "")
	if len(value) > fuzzMaxValueBytes {
		value = value[:fuzzMaxValueBytes]
	}
	return value
}

func fuzzRawBool(value string, fallback bool) bool {
	switch strings.ToLower(fuzzTrim(value)) {
	case "1", "t", "true", "yes", "y", "on":
		return true
	case "0", "f", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func fuzzRawToken(value string, limit int) string {
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
