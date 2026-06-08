// This package provides a mock server for testing fuzzing templates
package fuzzplayground

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/projectdiscovery/retryablehttp-go"
)

func GetPlaygroundServer() *echo.Echo {
	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())

	e.GET("/", indexHandler)
	e.GET("/info", infoHandler)
	e.GET("/redirect", redirectHandler)
	e.GET("/request", requestHandler)
	e.GET("/email", emailHandler)
	e.GET("/permissions", permissionsHandler)

	e.GET("/blog/post", numIdorHandler) // for num based idors like ?id=44
	e.POST("/reset-password", resetPasswordHandler)
	e.GET("/host-header-lab", hostHeaderLabHandler)
	e.GET("/user/:id/profile", userProfileHandler)
	e.POST("/user", patchUnsanitizedUserHandler)
	e.GET("/blog/posts", getPostsHandler)

	registerAnalyzerRoutes(e)
	return e
}

// registerAnalyzerRoutes wires a dedicated, analyzer-friendly test bench used by
// the fuzzer "analyzer" templates. Each endpoint is genuinely vulnerable but
// responds purely in-band and deterministically (no external network egress),
// so the corresponding analyzer's generic probes reliably trigger detection in
// CI. The query parameter is always "q" to keep the templates uniform.
func registerAnalyzerRoutes(e *echo.Echo) {
	e.GET("/analyzer/sqli", analyzerSQLiHandler)
	e.GET("/analyzer/ssti", analyzerSSTIHandler)
	e.GET("/analyzer/lfi", analyzerLFIHandler)
	e.GET("/analyzer/cmdi", analyzerCMDiHandler)
	e.GET("/analyzer/ssrf", analyzerSSRFHandler)
	e.GET("/analyzer/redirect", analyzerRedirectHandler)
	e.GET("/analyzer/crlf", analyzerCRLFHandler)
	e.GET("/analyzer/cors", analyzerCORSHandler)
	e.GET("/analyzer/host-header", analyzerHostHeaderHandler)

	// Benign counterparts: these reflect or echo input but are NOT vulnerable,
	// so the analyzers must NOT raise a finding against them (false-positive
	// guard at the CLI level).
	e.GET("/analyzer/safe/reflect", analyzerSafeReflectHandler)
	e.GET("/analyzer/safe/redirect", analyzerSafeRedirectHandler)
	e.GET("/analyzer/safe/cors", analyzerSafeCORSHandler)
	e.GET("/analyzer/safe/headers", analyzerSafeHeadersHandler)
	e.GET("/analyzer/safe/host", analyzerSafeHostHandler)

	// Non-query positions: prove the analyzers fuzz path / header / cookie / body
	// components through the real pipeline, not just query parameters.
	e.GET("/analyzer/path/sqli/:id", analyzerPathSQLiHandler)
	e.GET("/analyzer/header/sqli", analyzerHeaderSQLiHandler)
	e.POST("/analyzer/body/sqli", analyzerBodySQLiHandler)
	e.GET("/analyzer/cookie/ssti", analyzerCookieSSTIHandler)
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
func analyzerSQLiHandler(ctx echo.Context) error {
	q := ctx.QueryParam("q")
	posts, err := getUnsanitizedPostsByLang(db, q)
	if err != nil {
		return ctx.String(http.StatusInternalServerError, err.Error())
	}
	return ctx.JSON(http.StatusOK, posts)
}

// analyzerSSTIHandler evaluates arithmetic template expressions in q.
func analyzerSSTIHandler(ctx echo.Context) error {
	out := reArithmeticTemplate.ReplaceAllStringFunc(ctx.QueryParam("q"), func(m string) string {
		sub := reArithmeticTemplate.FindStringSubmatch(m)
		a, _ := strconv.Atoi(sub[1])
		b, _ := strconv.Atoi(sub[2])
		return strconv.Itoa(a * b)
	})
	return ctx.HTML(http.StatusOK, fmt.Sprintf(bodyTemplate, out))
}

// analyzerLFIHandler returns file contents for path-traversal payloads in q.
func analyzerLFIHandler(ctx echo.Context) error {
	q := ctx.QueryParam("q")
	switch {
	case strings.Contains(q, "etc/passwd"):
		return ctx.String(http.StatusOK, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
	case strings.Contains(strings.ToLower(q), "win.ini"):
		return ctx.String(http.StatusOK, "; for 16-bit app support\r\n[fonts]\r\n")
	default:
		return ctx.String(http.StatusOK, "file not found")
	}
}

// analyzerCMDiHandler simulates a shell that concatenates q: an injected
// separator followed by `id` yields command output.
func analyzerCMDiHandler(ctx echo.Context) error {
	q := ctx.QueryParam("q")
	for _, sep := range analyzerCmdiSeparators {
		if strings.Contains(q, sep) {
			return ctx.String(http.StatusOK, "uid=0(root) gid=0(root) groups=0(root)")
		}
	}
	return ctx.String(http.StatusOK, fmt.Sprintf("ping output for %s", q))
}

// analyzerSSRFHandler simulates an in-band SSRF: requesting a cloud metadata
// endpoint returns the (mock) instance identity document. It does NOT perform a
// real outbound request, keeping the test hermetic.
func analyzerSSRFHandler(ctx echo.Context) error {
	q := ctx.QueryParam("q")
	if strings.Contains(q, "169.254.169.254") || strings.Contains(q, "metadata.google.internal") {
		return ctx.String(http.StatusOK, `{"accountId":"123456789012","imageId":"ami-0abcd1234ef567890","instanceId":"i-0abcd1234ef567890","region":"us-east-1"}`)
	}
	return ctx.String(http.StatusOK, "fetched: nothing interesting")
}

// analyzerRedirectHandler reflects q straight into the Location header.
func analyzerRedirectHandler(ctx echo.Context) error {
	return ctx.Redirect(http.StatusFound, ctx.QueryParam("q"))
}

// analyzerCRLFHandler naively builds response headers from q, splitting on
// newlines — a textbook response-splitting bug.
func analyzerCRLFHandler(ctx echo.Context) error {
	for _, line := range strings.Split(ctx.QueryParam("q"), "\n") {
		line = strings.TrimRight(line, "\r")
		idx := strings.Index(line, ": ")
		if idx <= 0 || strings.ContainsAny(line[:idx], " \t") {
			continue
		}
		name, val := line[:idx], line[idx+2:]
		if strings.EqualFold(name, "Set-Cookie") {
			ctx.Response().Header().Add("Set-Cookie", val)
		} else {
			ctx.Response().Header().Set(name, val)
		}
	}
	return ctx.String(http.StatusOK, "ok")
}

// analyzerCORSHandler reflects an arbitrary Origin and allows credentials.
func analyzerCORSHandler(ctx echo.Context) error {
	if origin := ctx.Request().Header.Get("Origin"); origin != "" {
		ctx.Response().Header().Set("Access-Control-Allow-Origin", origin)
		ctx.Response().Header().Set("Access-Control-Allow-Credentials", "true")
	}
	return ctx.String(http.StatusOK, "ok")
}

// analyzerHostHeaderHandler reflects the (attacker-controlled) X-Forwarded-Host
// into an absolute link in the body, without performing any outbound request.
func analyzerHostHeaderHandler(ctx echo.Context) error {
	host := ctx.Request().Header.Get("X-Forwarded-Host")
	if host == "" {
		host = ctx.Request().Host
	}
	return ctx.HTML(http.StatusOK, fmt.Sprintf(`<a href="https://%s/reset?token=abc">reset</a>`, host))
}

// --- Benign handlers (must not trigger any analyzer) -----------------------

// analyzerSafeReflectHandler reflects q verbatim with no evaluation, no DB, no
// command execution and no file access; it is the benign counterpart for the
// ssti, sqli, cmdi, lfi and ssrf analyzers.
func analyzerSafeReflectHandler(ctx echo.Context) error {
	return ctx.HTML(http.StatusOK, fmt.Sprintf(bodyTemplate, "you searched for: "+ctx.QueryParam("q")))
}

// analyzerSafeRedirectHandler always redirects to a fixed trusted location,
// ignoring user input.
func analyzerSafeRedirectHandler(ctx echo.Context) error {
	return ctx.Redirect(http.StatusFound, "/home")
}

// analyzerSafeCORSHandler only ever allows a single trusted origin.
func analyzerSafeCORSHandler(ctx echo.Context) error {
	ctx.Response().Header().Set("Access-Control-Allow-Origin", "https://trusted.example.com")
	return ctx.String(http.StatusOK, "ok")
}

// analyzerSafeHeadersHandler returns static headers and never reflects input.
func analyzerSafeHeadersHandler(ctx echo.Context) error {
	ctx.Response().Header().Set("X-Static", "constant")
	return ctx.String(http.StatusOK, "ok")
}

// analyzerSafeHostHandler always builds links from a fixed, trusted host.
func analyzerSafeHostHandler(ctx echo.Context) error {
	return ctx.HTML(http.StatusOK, `<a href="https://app.example.com/reset?token=abc">reset</a>`)
}

// --- Non-query position handlers -------------------------------------------

// sqliFromValue runs the value through the real sqlite query so a quote yields a
// genuine "unrecognized token" error that the sqli_error analyzer fingerprints.
func sqliFromValue(ctx echo.Context, value string) error {
	posts, err := getUnsanitizedPostsByLang(db, value)
	if err != nil {
		return ctx.String(http.StatusInternalServerError, err.Error())
	}
	return ctx.JSON(http.StatusOK, posts)
}

// analyzerPathSQLiHandler is error-based SQLi on a path segment (:id).
func analyzerPathSQLiHandler(ctx echo.Context) error {
	return sqliFromValue(ctx, ctx.Param("id"))
}

// analyzerHeaderSQLiHandler is error-based SQLi on the X-Search request header.
func analyzerHeaderSQLiHandler(ctx echo.Context) error {
	return sqliFromValue(ctx, ctx.Request().Header.Get("X-Search"))
}

// analyzerBodySQLiHandler is error-based SQLi on the JSON body "name" field.
func analyzerBodySQLiHandler(ctx echo.Context) error {
	var payload struct {
		Name string `json:"name"`
	}
	body, _ := io.ReadAll(ctx.Request().Body)
	_ = json.Unmarshal(body, &payload)
	return sqliFromValue(ctx, payload.Name)
}

// analyzerCookieSSTIHandler evaluates arithmetic template expressions found in
// the "lang" cookie. SSTI (not SQLi) is used here because Go's cookie value
// sanitization strips the quotes SQLi relies on, whereas SSTI payload
// characters ({ } * $) are cookie-legal.
func analyzerCookieSSTIHandler(ctx echo.Context) error {
	val := "en"
	if c, err := ctx.Cookie("lang"); err == nil {
		val = c.Value
	}
	out := reArithmeticTemplate.ReplaceAllStringFunc(val, func(m string) string {
		sub := reArithmeticTemplate.FindStringSubmatch(m)
		a, _ := strconv.Atoi(sub[1])
		b, _ := strconv.Atoi(sub[2])
		return strconv.Itoa(a * b)
	})
	return ctx.HTML(http.StatusOK, fmt.Sprintf(bodyTemplate, "lang="+out))
}

var bodyTemplate = `<html>
<head>
<title>Fuzz Playground</title>
</head>
<body>
%s
</body>
</html>`

func indexHandler(ctx echo.Context) error {
	return ctx.HTML(200, fmt.Sprintf(bodyTemplate, `<h1>Fuzzing Playground</h1><hr>
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

func infoHandler(ctx echo.Context) error {
	return ctx.HTML(200, fmt.Sprintf(bodyTemplate, fmt.Sprintf("Name of user: %s%s%s", ctx.QueryParam("name"), ctx.QueryParam("another"), ctx.QueryParam("random"))))
}

func redirectHandler(ctx echo.Context) error {
	url := ctx.QueryParam("redirect_url")
	return ctx.Redirect(302, url)
}

func requestHandler(ctx echo.Context) error {
	url := ctx.QueryParam("url")
	data, err := retryablehttp.DefaultClient().Get(url)
	if err != nil {
		return ctx.HTML(500, err.Error())
	}
	defer func() {
		_ = data.Body.Close()
	}()

	body, _ := io.ReadAll(data.Body)
	return ctx.HTML(200, fmt.Sprintf(bodyTemplate, string(body)))
}

func emailHandler(ctx echo.Context) error {
	text := ctx.QueryParam("text")
	if strings.Contains(text, "{{") {
		trimmed := strings.SplitN(strings.Trim(text[strings.Index(text, "{"):], "{}"), "*", 2)
		if len(trimmed) < 2 {
			return ctx.HTML(500, "invalid template")
		}
		first, _ := strconv.Atoi(trimmed[0])
		second, _ := strconv.Atoi(trimmed[1])
		text = strconv.Itoa(first * second)
	}
	return ctx.HTML(200, fmt.Sprintf(bodyTemplate, fmt.Sprintf("Text: %s", text)))
}

func permissionsHandler(ctx echo.Context) error {
	command := ctx.QueryParam("cmd")
	fields := strings.Fields(command)
	cmd := exec.Command(fields[0], fields[1:]...)
	data, _ := cmd.CombinedOutput()

	return ctx.HTML(200, fmt.Sprintf(bodyTemplate, string(data)))
}

func numIdorHandler(ctx echo.Context) error {
	// validate if any numerical query param is present
	// if not, return 400 if so, return 200
	for k := range ctx.QueryParams() {
		if _, err := strconv.Atoi(ctx.QueryParam(k)); err == nil {
			return ctx.JSON(200, "Profile Info for user with id "+ctx.QueryParam(k))
		}
	}
	return ctx.JSON(400, "No numerical query param found")
}

func patchUnsanitizedUserHandler(ctx echo.Context) error {
	var user User

	contentType := ctx.Request().Header.Get("Content-Type")
	// manually handle unmarshalling data
	if strings.Contains(contentType, "application/json") {
		err := ctx.Bind(&user)
		if err != nil {
			return ctx.JSON(500, "Invalid JSON data")
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		user.Name = ctx.FormValue("name")
		user.Age, _ = strconv.Atoi(ctx.FormValue("age"))
		user.Role = ctx.FormValue("role")
		user.ID, _ = strconv.Atoi(ctx.FormValue("id"))
	} else if strings.Contains(contentType, "application/xml") {
		bin, _ := io.ReadAll(ctx.Request().Body)
		err := xml.Unmarshal(bin, &user)
		if err != nil {
			return ctx.JSON(500, "Invalid XML data")
		}
	} else if strings.Contains(contentType, "multipart/form-data") {
		user.Name = ctx.FormValue("name")
		user.Age, _ = strconv.Atoi(ctx.FormValue("age"))
		user.Role = ctx.FormValue("role")
		user.ID, _ = strconv.Atoi(ctx.FormValue("id"))
	} else {
		return ctx.JSON(500, "Invalid Content-Type")
	}

	err := patchUnsanitizedUser(db, user)
	if err != nil {
		return ctx.JSON(500, err.Error())
	}
	return ctx.JSON(200, "User updated successfully")
}

// resetPassword mock
func resetPasswordHandler(c echo.Context) error {
	var m map[string]interface{}
	if err := c.Bind(&m); err != nil {
		return c.JSON(500, "Something went wrong")
	}

	host := c.Request().Header.Get("X-Forwarded-For")
	if host == "" {
		return c.JSON(500, "Something went wrong")
	}
	resp, err := http.Get("http://internal." + host + "/update?user=1337&pass=" + m["password"].(string))
	if err != nil {
		return c.JSON(500, "Something went wrong")
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	return c.JSON(200, "Password reset successfully")
}

func hostHeaderLabHandler(c echo.Context) error {
	// vulnerable app has custom routing and trusts x-forwarded-host
	// to route to internal services
	if c.Request().Header.Get("X-Forwarded-Host") != "" {
		resp, err := http.Get("http://" + c.Request().Header.Get("X-Forwarded-Host"))
		if err != nil {
			return c.JSON(500, "Something went wrong")
		}
		defer func() {
			_ = resp.Body.Close()
		}()
		c.Response().Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		c.Response().WriteHeader(resp.StatusCode)
		_, err = io.Copy(c.Response().Writer, resp.Body)
		if err != nil {
			return c.JSON(500, "Something went wrong")
		}
	}
	return c.JSON(200, "Not a Teapot")
}

func userProfileHandler(ctx echo.Context) error {
	val, _ := url.PathUnescape(ctx.Param("id"))
	fmt.Printf("Unescaped: %s\n", val)
	user, err := getUnsanitizedUser(db, val)
	if err != nil {
		return ctx.JSON(500, err.Error())
	}
	return ctx.JSON(200, user)
}

func getPostsHandler(c echo.Context) error {
	lang, err := c.Cookie("lang")
	if err != nil {
		// If the language cookie is missing, default to English
		lang = new(http.Cookie)
		lang.Value = "en"
	}
	posts, err := getUnsanitizedPostsByLang(db, lang.Value)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, posts)
}
