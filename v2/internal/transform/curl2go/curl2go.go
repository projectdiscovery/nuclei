// Taken from https://github.com/kumakichi/curl-to-go/blob/master/curl_to_go.go.

package curl2go

import (
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/fuzzing"
	"github.com/projectdiscovery/retryablehttp-go"
)

type someResult struct {
	unflagged []string
	m         map[string]interface{}
}

type translator struct {
	cursor int // iterator position
	input  string
	result someResult
}

// Parse parses a curl command and returns the normalized request.
func Parse(curl string) (*fuzzing.NormalizedRequest, error) {
	// recover since curl->go parsing may crash.
	defer func() {
		_ = recover()
	}()

	curl = strings.ReplaceAll(strings.ReplaceAll(curl, "\\x0d", "\r"), "\\x0a", "\n")
	t := &translator{
		cursor: 0,
		input:  strings.TrimSpace(curl),
		result: someResult{
			m: make(map[string]interface{}),
		},
	}
	cmd := t.parseCommand()

	if cmd.unflagged[0] != "curl" {
		return nil, errors.New("invalid curl command")
	}
	data := extractRelevantPieces(cmd)

	req, err := http.NewRequest(data.method, data.url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not create request")
	}
	for k, v := range data.headers {
		req.Header.Set(k, v)
	}
	if data.data != "" {
		req.ContentLength = int64(len(data.data))
		req.Body = ioutil.NopCloser(strings.NewReader(data.data))
	}

	retryable, err := retryablehttp.FromRequest(req)
	if err != nil {
		return nil, errors.Wrap(err, "could not create retryable request")
	}

	normalized, err := fuzzing.NormalizeRequest(retryable)
	if err != nil {
		return nil, errors.Wrap(err, "could not create normalized request")
	}
	return normalized, nil
}

type someRelevant struct {
	url       string
	method    string
	headers   map[string]string
	data      string
	dataType  string
	insecure  bool
	basicauth ba
}

type ba struct {
	user string
	pass string
}

// extractRelevantPieces returns an object with relevant pieces
// extracted from cmd, the parsed command. This accounts for
// multiple flags that do the same thing and return structured
// data that makes it easy to spit out Go code.
func extractRelevantPieces(cmd someResult) *someRelevant {
	relevant := &someRelevant{dataType: "string"}

	// prefer --url over unnamed parameter, if it exists; keep first one only
	if v, ok := cmd.getMapSlice("url"); ok {
		if len(v) > 0 {
			relevant.url = v[0]
		}
	} else if len(cmd.unflagged) > 1 {
		relevant.url = cmd.unflagged[1] // position 1 because index 0 is the curl command itself
	}

	var someHeaders []string
	// gather the headers together
	if v, ok := cmd.getMapSlice("H"); ok {
		someHeaders = append(someHeaders, v...)
	}
	if v, ok := cmd.getMapSlice("header"); ok {
		someHeaders = append(someHeaders, v...)
	}
	if v, ok := cmd.getMapSlice("b"); ok {
		cookie := []string{"Cookie: " + strings.Join(v, " ")}
		someHeaders = append(someHeaders, cookie...)
	}
	relevant.headers = parseHeaders(someHeaders)

	// set method to HEAD?
	if _, ok := cmd.m["I"]; ok {
		relevant.method = "HEAD"
	} else if _, ok := cmd.m["head"]; ok {
		relevant.method = "HEAD"
	}

	// between -X and --request, prefer the long form I guess
	if v, ok := cmd.getMapSlice("request"); ok {
		if len(v) > 0 {
			relevant.method = strings.ToUpper(v[len(v)-1])
		}
	} else if v, ok := cmd.getMapSlice("X"); ok {
		if len(v) > 0 {
			relevant.method = strings.ToUpper(v[len(v)-1]) // if multiple, use last (according to curl docs)
		}
	} else if _, ok := cmd.getMapSlice("data-binary"); ok {
		relevant.method = "POST"  // if data-binary, user method POST
		relevant.dataType = "raw" // if data-binary, post body will be raw
	}

	// join multiple request body data, if any
	var dataASCII []string
	var loadData = func(d []string) {
		if relevant.method == "" {
			relevant.method = "POST"
		}

		// according to issue #8, curl adds a default Content-Type
		// header if one is not set explicitly
		if relevant.headers["Content-Type"] == "" {
			relevant.headers["Content-Type"] = "application/x-www-form-urlencoded"
		}

		for i := 0; i < len(d); i++ {
			dataASCII = append(dataASCII, d[i])
		}
	}
	if v, ok := cmd.getMapSlice("d"); ok {
		loadData(v)
	}
	if v, ok := cmd.getMapSlice("data"); ok {
		loadData(v)
	}
	if v, ok := cmd.getMapSlice("data-raw"); ok {
		loadData(v)
	}
	if v, ok := cmd.getMapSlice("data-binary"); ok {
		loadData(v)
	}
	if len(dataASCII) > 0 {
		relevant.data = strings.Join(dataASCII, "&")
	}

	// between -u and --user, choose the long form...
	var basicAuthString = ""
	if v, ok := cmd.getMapSlice("user"); ok {
		if len(v) > 0 {
			basicAuthString = v[len(v)-1]
		}
	} else if v, ok := cmd.getMapSlice("u"); ok {
		basicAuthString = v[len(v)-1]
	}
	// if the -u or --user flags haven"t been set then don"t set the
	// basicauth property.
	if basicAuthString != "" {
		var basicAuthSplit = strings.Index(basicAuthString, ":")
		if basicAuthSplit > -1 {
			relevant.basicauth = ba{
				user: basicAuthString[0:basicAuthSplit],
				pass: basicAuthString[basicAuthSplit+1:],
			}
		} else {
			// the user has not provided a password
			relevant.basicauth = ba{user: basicAuthString, pass: "<PASSWORD>"}
		}
	}

	// default to GET if nothing else specified
	if relevant.method == "" {
		relevant.method = "GET"
	}

	if _, ok := cmd.m["k"]; ok {
		relevant.insecure = true
	} else if _, ok := cmd.m["insecure"]; ok {
		relevant.insecure = true
	}
	return relevant
}

// parseHeaders converts an array of header strings (like "Content-Type: foo")
// into a map of key/values. It assumes header field names are unique.
func parseHeaders(stringHeaders []string) map[string]string {
	headers := make(map[string]string)
	for i := range stringHeaders {
		split := strings.Index(stringHeaders[i], ":")
		if split == -1 {
			continue
		}
		name := strings.TrimSpace(stringHeaders[i][:split])
		value := strings.TrimSpace(stringHeaders[i][split+1:])
		headers[toTitleCase(name)] = value
	}

	return headers
}

func replaceAllStringSubmatchFunc(re *regexp.Regexp, str string, repl func([]string) string) string {
	result := ""
	lastIndex := 0

	for _, v := range re.FindAllSubmatchIndex([]byte(str), -1) {
		groups := []string{}
		for i := 0; i < len(v); i += 2 {
			groups = append(groups, str[v[i]:v[i+1]])
		}

		//result += repl(groups)
		result += str[lastIndex:v[0]] + repl(groups)
		lastIndex = v[1]
	}

	return result + str[lastIndex:]
}

var r = regexp.MustCompile(`\w*`)

func toTitleCase(str string) string {
	return replaceAllStringSubmatchFunc(r, str, func(groups []string) string {
		txt := groups[0]
		return strings.ToUpper(txt[:1]) + strings.ToLower(txt[1:])
	})
}

// goExpandEnv adds surrounding quotes around s to make it a Go string,
// escaping any characters as needed. It checks to see if s has an
// environment variable in it. If so, it returns s wrapped in a Go
// func that expands the environment variable. Otherwise, it
// returns s wrapped in quotes and escaped for use in Go strings.
// s should not already be escaped! This func always returns a Go
// string value.
func goExpandEnv(s string) string {
	pos := strings.Index(s, "$")
	if pos > -1 {
		if pos > 0 && s[pos-1] == '\\' {
			// The $ is escaped, so strip the escaping backslash
			return s[:pos-1] + s[pos:]
		} else {
			// $ is not escaped, so treat it as an env variable
			return "os.ExpandEnv(\"" + goEsc(s) + "\")"
		}
	}
	return "\"" + goEsc(s) + "\""
}

// goEsc escapes characters in s so that it is safe to use s in
// a "quoted string" in a Go program
func goEsc(s string) string {
	s = strings.Replace(s, "\\", "\\\\", -1)
	s = strings.Replace(s, "\"", "\\\"", -1)
	return s
}

func (t *translator) parseCommand() someResult {
	// trim leading $ or # that may have been left in
	t.input = strings.TrimSpace(t.input)
	if len(t.input) > 2 && (t.input[0] == '$' || t.input[0] == '#') && whitespace(t.input[1]) {
		t.input = strings.TrimSpace(t.input[1:])
	}

	for t.cursor = 0; t.cursor < len(t.input); t.cursor++ {
		t.skipWhitespace()
		if t.input[t.cursor] == '-' {
			t.flagSet()
		} else {
			t.unflagged()
		}
	}
	return t.result
}

// flagSet handles flags and it assumes the current t.cursor
// points to a first dash.
func (t *translator) flagSet() {
	// long flag form?
	if t.cursor < len(t.input)-1 && t.input[t.cursor+1] == '-' {
		t.longFlag()
		return
	}
	// if not, parse short flag form
	t.cursor++ // skip leading dash
	var flagName string
	for t.cursor < len(t.input) && !whitespace(t.input[t.cursor]) {
		flagName = string(t.input[t.cursor])
		if _, ok := t.result.m[flagName]; !ok {
			t.result.m[flagName] = make([]string, 0)
		}
		t.cursor++ // skip the flag name
		if boolFlag(flagName) {
			t.result.m[flagName] = true
		} else if v, ok := t.result.m[flagName].([]string); ok {
			t.result.m[flagName] = append(v, t.nextString())
		}
	}
}

// longFlag consumes a "--long-flag" sequence and
// stores it in t.result.
func (t *translator) longFlag() {
	t.cursor += 2 // skip leading dashes
	var flagName = t.nextString('=')
	if boolFlag(flagName) {
		t.result.m[flagName] = true
	} else {
		if _, ok := t.result.m[flagName]; !ok {
			t.result.m[flagName] = make([]string, 0)
		}

		if v, ok := t.result.m[flagName].([]string); ok {
			t.result.m[flagName] = append(v, t.nextString())
		}
	}
}

// unflagged consumes the next string as an unflagged value,
// storing it in the t.result.
func (t *translator) unflagged() {
	t.result.unflagged = append(t.result.unflagged, t.nextString())
}

// boolFlag returns whether a flag is known to be boolean type
func boolFlag(flag string) bool {
	_, ok := boolOptions[flag]
	return ok
}

// nextString skips any leading whitespace and consumes the next
// space-delimited string value and returns it. If endChar is set,
// it will be used to determine the end of the string. Normally just
// unescaped whitespace is the end of the string, but endChar can
// be used to specify another end-of-string. This func honors \
// as an escape character and does not include it in the value, except
// in the special case of the \$ sequence, the backslash is retained
// so other code can decide whether to treat as an env var or not.
func (t *translator) nextString(endChar ...byte) string {
	t.skipWhitespace()

	var str = ""

	var quoted = false
	var quoteCh byte = ' '
	var escaped = false
	var quoteDS = false // Dollar-Single-Quotes

	for ; t.cursor < len(t.input); t.cursor++ {
		if quoted {
			if t.input[t.cursor] == quoteCh && !escaped && t.input[t.cursor-1] != '\\' {
				quoted = false
				continue
			}
		}
		if !quoted {
			if !escaped {
				if whitespace(t.input[t.cursor]) {
					return str
				}
				if t.input[t.cursor] == '"' || t.input[t.cursor] == '\'' {
					quoted = true
					quoteCh = t.input[t.cursor]
					if str+string(quoteCh) == "$'" {
						quoteDS = true
						str = ""
					}
					t.cursor++
				}
				if len(endChar) > 0 && t.input[t.cursor] == endChar[0] {
					t.cursor++ // skip the endChar
					return str
				}
			}
		}
		if !escaped && !quoteDS && t.input[t.cursor] == '\\' {
			escaped = true
			// skip the backslash unless the next character is $
			if !(t.cursor < len(t.input)-1 && t.input[t.cursor+1] == '$') {
				continue
			}
		}

		str += string(t.input[t.cursor])
		escaped = false
	}

	return str
}

// skipWhitespace skips whitespace between tokens, taking into account escaped whitespace.
func (t *translator) skipWhitespace() {
	for ; t.cursor < len(t.input); t.cursor++ {
		for t.input[t.cursor] == '\\' && (t.cursor < len(t.input)-1 && whitespace(t.input[t.cursor+1])) {
			t.cursor++
		}

		if !whitespace(t.input[t.cursor]) {
			break
		}
	}
}

// whitespace returns true if ch is a whitespace character.
func whitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

var boolOptions = map[string]struct{}{
	"#":                     {},
	"progress-bar":          {},
	"-":                     {},
	"next":                  {},
	"0":                     {},
	"http1.0":               {},
	"http1.1":               {},
	"http2":                 {},
	"no-npn":                {},
	"no-alpn":               {},
	"1":                     {},
	"tlsv1":                 {},
	"2":                     {},
	"sslv2":                 {},
	"3":                     {},
	"sslv3":                 {},
	"4":                     {},
	"ipv4":                  {},
	"6":                     {},
	"ipv6":                  {},
	"a":                     {},
	"append":                {},
	"anyauth":               {},
	"B":                     {},
	"use-ascii":             {},
	"basic":                 {},
	"compressed":            {},
	"create-dirs":           {},
	"crlf":                  {},
	"digest":                {},
	"disable-eprt":          {},
	"disable-epsv":          {},
	"environment":           {},
	"cert-status":           {},
	"false-start":           {},
	"f":                     {},
	"fail":                  {},
	"ftp-create-dirs":       {},
	"ftp-pasv":              {},
	"ftp-skip-pasv-ip":      {},
	"ftp-pret":              {},
	"ftp-ssl-ccc":           {},
	"ftp-ssl-control":       {},
	"g":                     {},
	"globoff":               {},
	"G":                     {},
	"get":                   {},
	"ignore-content-length": {},
	"i":                     {},
	"include":               {},
	"I":                     {},
	"head":                  {},
	"j":                     {},
	"junk-session-cookies":  {},
	"J":                     {},
	"remote-header-name":    {},
	"k":                     {},
	"insecure":              {},
	"l":                     {},
	"list-only":             {},
	"L":                     {},
	"location":              {},
	"location-trusted":      {},
	"metalink":              {},
	"n":                     {},
	"netrc":                 {},
	"N":                     {},
	"no-buffer":             {},
	"netrc-file":            {},
	"netrc-optional":        {},
	"negotiate":             {},
	"no-keepalive":          {},
	"no-sessionid":          {},
	"ntlm":                  {},
	"O":                     {},
	"remote-name":           {},
	"oauth2-bearer":         {},
	"p":                     {},
	"proxy-tunnel":          {},
	"path-as-is":            {},
	"post301":               {},
	"post302":               {},
	"post303":               {},
	"proxy-anyauth":         {},
	"proxy-basic":           {},
	"proxy-digest":          {},
	"proxy-negotiate":       {},
	"proxy-ntlm":            {},
	"q":                     {},
	"raw":                   {},
	"remote-name-all":       {},
	"s":                     {},
	"silent":                {},
	"sasl-ir":               {},
	"S":                     {},
	"show-error":            {},
	"ssl":                   {},
	"ssl-reqd":              {},
	"ssl-allow-beast":       {},
	"ssl-no-revoke":         {},
	"socks5-gssapi-nec":     {},
	"tcp-nodelay":           {},
	"tlsv1.0":               {},
	"tlsv1.1":               {},
	"tlsv1.2":               {},
	"tr-encoding":           {},
	"trace-time":            {},
	"v":                     {},
	"verbose":               {},
	"xattr":                 {},
	"h":                     {},
	"help":                  {},
	"M":                     {},
	"manual":                {},
	"V":                     {},
	"version":               {},
}

func (c *someResult) getMapSlice(key string) ([]string, bool) {
	v, ok := c.m[key]
	if !ok {
		return nil, false
	}

	vv, ok := v.([]string)
	if !ok {
		return nil, false
	}

	return vv, true
}
