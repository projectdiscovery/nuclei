// This package provides a mock server for testing fuzzing templates
package fuzzplayground

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/projectdiscovery/retryablehttp-go"
)

// PlaygroundServer wraps the fuzz playground handler with the lifecycle methods
// used by the integration tests and the standalone playground command.
type PlaygroundServer struct {
	handler http.Handler
	server  *http.Server
}

func GetPlaygroundServer() *PlaygroundServer {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", indexHandler)
	mux.HandleFunc("GET /info", infoHandler)
	mux.HandleFunc("GET /redirect", redirectHandler)
	mux.HandleFunc("GET /request", requestHandler)
	mux.HandleFunc("GET /email", emailHandler)
	mux.HandleFunc("GET /permissions", permissionsHandler)

	mux.HandleFunc("GET /blog/post", numIdorHandler) // for num based idors like ?id=44
	mux.HandleFunc("POST /reset-password", resetPasswordHandler)
	mux.HandleFunc("GET /host-header-lab", hostHeaderLabHandler)
	mux.HandleFunc("GET /user/{id}/profile", userProfileHandler)
	mux.HandleFunc("POST /user", patchUnsanitizedUserHandler)
	mux.HandleFunc("GET /blog/posts", getPostsHandler)

	registerAnalyzerRoutes(mux)
	registerAuthRoutes(mux)

	handler := recoverPlaygroundRequest(logPlaygroundRequest(mux))
	return &PlaygroundServer{handler: handler}
}

func (s *PlaygroundServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *PlaygroundServer) Start(addr string) error {
	s.server = &http.Server{
		Addr:    addr,
		Handler: s.handler,
	}
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *PlaygroundServer) Close() error {
	if s.server == nil {
		return nil
	}
	return s.server.Close()
}

// registerAnalyzerRoutes wires a dedicated, analyzer-friendly test bench used by
// the fuzzer "analyzer" templates. Each endpoint is genuinely vulnerable but
// responds purely in-band and deterministically (no external network egress),
// so the corresponding analyzer's generic probes reliably trigger detection in
// CI. The query parameter is always "q" to keep the templates uniform.
func registerAnalyzerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /analyzer/sqli", analyzerSQLiHandler)
	mux.HandleFunc("GET /analyzer/ssti", analyzerSSTIHandler)
	mux.HandleFunc("GET /analyzer/lfi", analyzerLFIHandler)
	mux.HandleFunc("GET /analyzer/cmdi", analyzerCMDiHandler)
	mux.HandleFunc("GET /analyzer/ssrf", analyzerSSRFHandler)
	mux.HandleFunc("GET /analyzer/redirect", analyzerRedirectHandler)
	mux.HandleFunc("GET /analyzer/crlf", analyzerCRLFHandler)
	mux.HandleFunc("GET /analyzer/cors", analyzerCORSHandler)
	mux.HandleFunc("GET /analyzer/host-header", analyzerHostHeaderHandler)

	// Benign counterparts: these reflect or echo input but are NOT vulnerable,
	// so the analyzers must NOT raise a finding against them (false-positive
	// guard at the CLI level).
	mux.HandleFunc("GET /analyzer/safe/reflect", analyzerSafeReflectHandler)
	mux.HandleFunc("GET /analyzer/safe/redirect", analyzerSafeRedirectHandler)
	mux.HandleFunc("GET /analyzer/safe/cors", analyzerSafeCORSHandler)
	mux.HandleFunc("GET /analyzer/safe/headers", analyzerSafeHeadersHandler)
	mux.HandleFunc("GET /analyzer/safe/host", analyzerSafeHostHandler)

	// Non-query positions: prove the analyzers fuzz path / header / cookie / body
	// components through the real pipeline, not just query parameters.
	mux.HandleFunc("GET /analyzer/path/sqli/{id}", analyzerPathSQLiHandler)
	mux.HandleFunc("GET /analyzer/header/sqli", analyzerHeaderSQLiHandler)
	mux.HandleFunc("POST /analyzer/body/sqli", analyzerBodySQLiHandler)
	mux.HandleFunc("GET /analyzer/cookie/ssti", analyzerCookieSSTIHandler)
}

// reArithmeticTemplate emulates a real template engine: it matches an arithmetic
// multiplication wrapped in a delimiter pair (EL ${}, Jinja {{}}, #{}, *{},
// Razor @(), ERB <%= %>, Smarty {}) and replaces the WHOLE delimited expression
// with its product, preserving any surrounding text (e.g. the analyzer's
// sentinels), exactly as a vulnerable engine would.
var reArithmeticTemplate = regexp.MustCompile(`(?:\$\{|\{\{|#\{|\*\{|@\(|<%=|\{)\s*(\d+)\s*\*\s*(\d+)\s*(?:\}\}|%>|\}|\))`)

// analyzerCmdiSeparators are shell metacharacter sequences followed by the `id`
// command that the cmdi analyzer injects; presence of any indicates the input
// reached a shell.
var analyzerCmdiSeparators = []string{";id", "|id", "||id", "&&id", "&id", "`id`", "$(id)", "\nid"}

// analyzerSQLiHandler is vulnerable to error-based SQLi via the real sqlite DB:
// a quote in q breaks the query and surfaces a genuine "unrecognized token"
// sqlite error, which the sqli_error analyzer fingerprints.
func analyzerSQLiHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	posts, err := getUnsanitizedPostsByLang(db, q)
	if err != nil {
		writeString(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, posts)
}

// analyzerSSTIHandler evaluates arithmetic template expressions in q.
func analyzerSSTIHandler(w http.ResponseWriter, r *http.Request) {
	out := reArithmeticTemplate.ReplaceAllStringFunc(r.URL.Query().Get("q"), func(m string) string {
		sub := reArithmeticTemplate.FindStringSubmatch(m)
		a, _ := strconv.Atoi(sub[1])
		b, _ := strconv.Atoi(sub[2])
		return strconv.Itoa(a * b)
	})
	writeHTML(w, http.StatusOK, fmt.Sprintf(bodyTemplate, out))
}

// analyzerLFIHandler returns file contents for path-traversal payloads in q.
func analyzerLFIHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	switch {
	case strings.Contains(q, "etc/passwd"):
		writeString(w, http.StatusOK, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
	case strings.Contains(strings.ToLower(q), "win.ini"):
		writeString(w, http.StatusOK, "; for 16-bit app support\r\n[fonts]\r\n")
	default:
		writeString(w, http.StatusOK, "file not found")
	}
}

// analyzerCMDiHandler simulates a shell that concatenates q: an injected
// separator followed by `id` yields command output.
func analyzerCMDiHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	for _, sep := range analyzerCmdiSeparators {
		if strings.Contains(q, sep) {
			writeString(w, http.StatusOK, "uid=0(root) gid=0(root) groups=0(root)")
			return
		}
	}
	writeString(w, http.StatusOK, fmt.Sprintf("ping output for %s", q))
}

// analyzerSSRFHandler simulates an in-band SSRF: requesting a cloud metadata
// endpoint returns the (mock) instance identity document. It does NOT perform a
// real outbound request, keeping the test hermetic.
func analyzerSSRFHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if strings.Contains(q, "169.254.169.254") || strings.Contains(q, "metadata.google.internal") {
		writeString(w, http.StatusOK, `{"accountId":"123456789012","imageId":"ami-0abcd1234ef567890","instanceId":"i-0abcd1234ef567890","region":"us-east-1"}`)
		return
	}
	writeString(w, http.StatusOK, "fetched: nothing interesting")
}

// analyzerRedirectHandler reflects q straight into the Location header.
func analyzerRedirectHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("q"), http.StatusFound)
}

// analyzerCRLFHandler naively builds response headers from q, splitting on
// newlines — a textbook response-splitting bug.
func analyzerCRLFHandler(w http.ResponseWriter, r *http.Request) {
	for _, line := range strings.Split(r.URL.Query().Get("q"), "\n") {
		line = strings.TrimRight(line, "\r")
		idx := strings.Index(line, ": ")
		if idx <= 0 || strings.ContainsAny(line[:idx], " \t") {
			continue
		}
		name, val := line[:idx], line[idx+2:]
		if strings.EqualFold(name, "Set-Cookie") {
			w.Header().Add("Set-Cookie", val)
		} else {
			w.Header().Set(name, val)
		}
	}
	writeString(w, http.StatusOK, "ok")
}

// analyzerCORSHandler reflects an arbitrary Origin and allows credentials.
func analyzerCORSHandler(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	writeString(w, http.StatusOK, "ok")
}

// analyzerHostHeaderHandler reflects the (attacker-controlled) X-Forwarded-Host
// into an absolute link in the body, without performing any outbound request.
func analyzerHostHeaderHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	writeHTML(w, http.StatusOK, fmt.Sprintf(`<a href="https://%s/reset?token=abc">reset</a>`, host))
}

// --- Benign handlers (must not trigger any analyzer) -----------------------

// analyzerSafeReflectHandler reflects q verbatim with no evaluation, no DB, no
// command execution and no file access; it is the benign counterpart for the
// ssti, sqli, cmdi, lfi and ssrf analyzers.
func analyzerSafeReflectHandler(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, http.StatusOK, fmt.Sprintf(bodyTemplate, "you searched for: "+r.URL.Query().Get("q")))
}

// analyzerSafeRedirectHandler always redirects to a fixed trusted location,
// ignoring user input.
func analyzerSafeRedirectHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/home", http.StatusFound)
}

// analyzerSafeCORSHandler only ever allows a single trusted origin.
func analyzerSafeCORSHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example.com")
	writeString(w, http.StatusOK, "ok")
}

// analyzerSafeHeadersHandler returns static headers and never reflects input.
func analyzerSafeHeadersHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("X-Static", "constant")
	writeString(w, http.StatusOK, "ok")
}

// analyzerSafeHostHandler always builds links from a fixed, trusted host.
func analyzerSafeHostHandler(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, http.StatusOK, `<a href="https://app.example.com/reset?token=abc">reset</a>`)
}

// --- Non-query position handlers -------------------------------------------

// sqliFromValue runs the value through the real sqlite query so a quote yields a
// genuine "unrecognized token" error that the sqli_error analyzer fingerprints.
func sqliFromValue(w http.ResponseWriter, value string) {
	posts, err := getUnsanitizedPostsByLang(db, value)
	if err != nil {
		writeString(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, posts)
}

// analyzerPathSQLiHandler is error-based SQLi on a path segment ({id}).
func analyzerPathSQLiHandler(w http.ResponseWriter, r *http.Request) {
	sqliFromValue(w, r.PathValue("id"))
}

// analyzerHeaderSQLiHandler is error-based SQLi on the X-Search request header.
func analyzerHeaderSQLiHandler(w http.ResponseWriter, r *http.Request) {
	sqliFromValue(w, r.Header.Get("X-Search"))
}

// analyzerBodySQLiHandler is error-based SQLi on the JSON body "name" field.
func analyzerBodySQLiHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Name string `json:"name"`
	}
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &payload)
	sqliFromValue(w, payload.Name)
}

// analyzerCookieSSTIHandler evaluates arithmetic template expressions found in
// the "lang" cookie. SSTI (not SQLi) is used here because Go's cookie value
// sanitization strips the quotes SQLi relies on, whereas SSTI payload
// characters ({ } * $) are cookie-legal.
func analyzerCookieSSTIHandler(w http.ResponseWriter, r *http.Request) {
	val := "en"
	if c, err := r.Cookie("lang"); err == nil {
		val = c.Value
	}
	out := reArithmeticTemplate.ReplaceAllStringFunc(val, func(m string) string {
		sub := reArithmeticTemplate.FindStringSubmatch(m)
		a, _ := strconv.Atoi(sub[1])
		b, _ := strconv.Atoi(sub[2])
		return strconv.Itoa(a * b)
	})
	writeHTML(w, http.StatusOK, fmt.Sprintf(bodyTemplate, "lang="+out))
}

var bodyTemplate = `<html>
<head>
<title>Fuzz Playground</title>
</head>
<body>
%s
</body>
</html>`

func indexHandler(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, http.StatusOK, fmt.Sprintf(bodyTemplate, `<h1>Fuzzing Playground</h1><hr>
	<ul>
		
	<li><a href="/info?name=test&another=value&random=data">Info Page XSS</a></li>
	<li><a href="/redirect?redirect_url=/info?name=redirected_from_url">Redirect Page OpenRedirect</a></li>
	<li><a href="/request?url=https://example.com">Request Page SSRF</a></li>
	<li><a href="/email?text=important_user">Email Page SSTI</a></li>
	<li><a href="/permissions?cmd=whoami">Permissions Page CMDI</a></li>
	
	<li><a href="/host-header-lab">Host Header Lab (X-Forwarded-Host Trusted)</a></li>
	<li><a href="/user/75/profile">User Profile Page SQLI (path parameter)</a></li>
	<li><a href="/user">POST on /user SQLI (body parameter)</a></li>
	<li><a href="/blog/posts">SQLI in cookie lang parameter value (eg. lang=en)</a></li>

	<li><a href="/analyzer/sqli?q=en">Analyzer bench: SQLi (query)</a></li>
	<li><a href="/analyzer/ssti?q=test">Analyzer bench: SSTI (query)</a></li>
	<li><a href="/analyzer/lfi?q=home.txt">Analyzer bench: LFI (query)</a></li>
	<li><a href="/analyzer/cmdi?q=127.0.0.1">Analyzer bench: CMDi (query)</a></li>
	<li><a href="/analyzer/ssrf?q=https://example.com">Analyzer bench: SSRF (query)</a></li>
	<li><a href="/analyzer/redirect?q=/dashboard">Analyzer bench: Open Redirect (query)</a></li>
	<li><a href="/analyzer/crlf?q=/home">Analyzer bench: CRLF (query)</a></li>
	<li><a href="/analyzer/cors?q=x">Analyzer bench: CORS (query)</a></li>
	<li><a href="/analyzer/host-header?q=x">Analyzer bench: Host Header Injection (query)</a></li>
	
	</ul>
`))
}

func infoHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	writeHTML(w, http.StatusOK, fmt.Sprintf(bodyTemplate, fmt.Sprintf("Name of user: %s%s%s", query.Get("name"), query.Get("another"), query.Get("random"))))
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("redirect_url"), http.StatusFound)
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	requestURL := r.URL.Query().Get("url")
	data, err := retryablehttp.DefaultClient().Get(requestURL)
	if err != nil {
		writeHTML(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() {
		_ = data.Body.Close()
	}()

	body, _ := io.ReadAll(data.Body)
	writeHTML(w, http.StatusOK, fmt.Sprintf(bodyTemplate, string(body)))
}

func emailHandler(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("text")
	if strings.Contains(text, "{{") {
		trimmed := strings.SplitN(strings.Trim(text[strings.Index(text, "{"):], "{}"), "*", 2)
		if len(trimmed) < 2 {
			writeHTML(w, http.StatusInternalServerError, "invalid template")
			return
		}
		first, _ := strconv.Atoi(trimmed[0])
		second, _ := strconv.Atoi(trimmed[1])
		text = strconv.Itoa(first * second)
	}
	writeHTML(w, http.StatusOK, fmt.Sprintf(bodyTemplate, fmt.Sprintf("Text: %s", text)))
}

func permissionsHandler(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	fields := strings.Fields(command)
	cmd := exec.Command(fields[0], fields[1:]...)
	data, _ := cmd.CombinedOutput()

	writeHTML(w, http.StatusOK, fmt.Sprintf(bodyTemplate, string(data)))
}

func numIdorHandler(w http.ResponseWriter, r *http.Request) {
	// validate if any numerical query param is present
	// if not, return 400 if so, return 200
	for k := range r.URL.Query() {
		value := r.URL.Query().Get(k)
		if _, err := strconv.Atoi(value); err == nil {
			writeJSON(w, http.StatusOK, "Profile Info for user with id "+value)
			return
		}
	}
	writeJSON(w, http.StatusBadRequest, "No numerical query param found")
}

func patchUnsanitizedUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User

	contentType := r.Header.Get("Content-Type")
	// manually handle unmarshalling data
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			writeJSON(w, http.StatusInternalServerError, "Invalid JSON data")
			return
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		user.Name = r.FormValue("name")
		user.Age, _ = strconv.Atoi(r.FormValue("age"))
		user.Role = r.FormValue("role")
		user.ID, _ = strconv.Atoi(r.FormValue("id"))
	} else if strings.Contains(contentType, "application/xml") {
		bin, _ := io.ReadAll(r.Body)
		err := xml.Unmarshal(bin, &user)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, "Invalid XML data")
			return
		}
	} else if strings.Contains(contentType, "multipart/form-data") {
		user.Name = r.FormValue("name")
		user.Age, _ = strconv.Atoi(r.FormValue("age"))
		user.Role = r.FormValue("role")
		user.ID, _ = strconv.Atoi(r.FormValue("id"))
	} else {
		writeJSON(w, http.StatusInternalServerError, "Invalid Content-Type")
		return
	}

	err := patchUnsanitizedUser(db, user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, "User updated successfully")
}

// resetPassword mock
func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var m map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		writeJSON(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	host := r.Header.Get("X-Forwarded-For")
	if host == "" {
		writeJSON(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	password, ok := m["password"].(string)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	resp, err := http.Get("http://internal." + host + "/update?user=1337&pass=" + password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	writeJSON(w, http.StatusOK, "Password reset successfully")
}

func hostHeaderLabHandler(w http.ResponseWriter, r *http.Request) {
	// vulnerable app has custom routing and trusts x-forwarded-host
	// to route to internal services
	if r.Header.Get("X-Forwarded-Host") != "" {
		resp, err := http.Get("http://" + r.Header.Get("X-Forwarded-Host"))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, "Something went wrong")
			return
		}
		defer func() {
			_ = resp.Body.Close()
		}()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, err = io.Copy(w, resp.Body)
		if err != nil {
			return
		}
		return
	}
	writeJSON(w, http.StatusOK, "Not a Teapot")
}

func userProfileHandler(w http.ResponseWriter, r *http.Request) {
	val, _ := url.PathUnescape(r.PathValue("id"))
	fmt.Printf("Unescaped: %s\n", val)
	user, err := getUnsanitizedUser(db, val)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func getPostsHandler(w http.ResponseWriter, r *http.Request) {
	lang, err := r.Cookie("lang")
	if err != nil {
		// If the language cookie is missing, default to English
		lang = new(http.Cookie)
		lang.Value = "en"
	}
	posts, err := getUnsanitizedPostsByLang(db, lang.Value)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, posts)
}

func writeHTML(w http.ResponseWriter, statusCode int, value string) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(statusCode)
	_, _ = io.WriteString(w, value)
}

func writeJSON(w http.ResponseWriter, statusCode int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(value)
}

func writeString(w http.ResponseWriter, statusCode int, value string) {
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.WriteHeader(statusCode)
	_, _ = io.WriteString(w, value)
}

func recoverPlaygroundRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func logPlaygroundRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}
