package javascript

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

// nonHTTPModules are nuclei JS libraries that each speak one dedicated wire
// protocol. None of them can produce a meaningful exchange with an HTTP server.
var nonHTTPModules = map[string]struct{}{
	"smb": {}, "smbsession": {}, "ssh": {}, "mysql": {}, "mssql": {},
	"postgres": {}, "oracle": {}, "redis": {}, "ldap": {}, "vnc": {},
	"rdp": {}, "rsync": {}, "smtp": {}, "pop3": {}, "telnet": {},
	"ikev2": {}, "kerberos": {}, "krbforge": {}, "krbroast": {},
	"dcerpc": {}, "dcom": {}, "scmr": {}, "secretsdump": {}, "tsch": {},
	"wmi": {}, "goexec": {},
}

// neutralModules open no connection of their own, so they do not change what a
// script can speak.
var neutralModules = map[string]struct{}{
	"bytes": {}, "structs": {}, "fs": {}, "goconsole": {},
}

var (
	requireCall    = regexp.MustCompile(`require\s*\(`)
	requireLiteral = regexp.MustCompile(`require\s*\(\s*["']nuclei/([a-z0-9_]+)["']\s*\)`)
)

// speaksOnlyNonHTTP reports whether the scripts can only talk dedicated
// non-HTTP protocols. Anything uncertain returns false, so the template runs:
// raw sockets (net), HTTP-capable libraries (http, websocket, grpc), unknown
// libraries, no library at all, or a require() whose module is not a literal.
func speaksOnlyNonHTTP(scripts ...string) bool {
	calls, protocol := 0, 0
	for _, script := range scripts {
		calls += len(requireCall.FindAllStringIndex(script, -1))
		for _, m := range requireLiteral.FindAllStringSubmatch(script, -1) {
			calls--
			name := m[1]
			if _, ok := neutralModules[name]; ok {
				continue
			}
			if _, ok := nonHTTPModules[name]; !ok {
				return false
			}
			protocol++
		}
	}
	return calls == 0 && protocol > 0
}

// skipOnHTTPPort reports whether this execution should not run: the template
// only speaks non-HTTP protocols, its declared port was replaced by the input's
// explicit port, and that host:port answered HTTP. In every other case the
// template runs.
func (request *Request) skipOnHTTPPort(ctx context.Context, declaredPort string, input *contextargs.Context, hostPort string) bool {
	if !request.nonHTTPOnly || declaredPort == "" || request.options == nil || request.options.HTTPService == nil {
		return false
	}
	_, effectivePort, err := net.SplitHostPort(hostPort)
	if err != nil || effectivePort == "" || effectivePort == declaredPort {
		return false
	}
	useTLS := strings.HasPrefix(strings.ToLower(input.MetaInput.Input), "https://")
	if !request.options.HTTPService.SpeaksHTTP(ctx, hostPort, useTLS) {
		return false
	}
	gologger.Verbose().Msgf("[%s] Skipped on %s: the port answers HTTP and the template only speaks non-HTTP protocols (declared port %s)", request.options.TemplateID, hostPort, declaredPort)
	return true
}

// requestsPerPort is the number of requests one port of this template counts
// in the progress total, so a skip can account for all of them.
func (request *Request) requestsPerPort() int {
	n := 1
	if request.generator != nil {
		n = request.generator.NewIterator().Total()
	}
	if request.PreCondition != "" {
		n++
	}
	return n
}

func skipReason(declaredPort string) string {
	return fmt.Sprintf("skipped: port answers HTTP, template speaks a non-HTTP protocol on port %s", declaredPort)
}
