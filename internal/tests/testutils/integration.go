package testutils

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/gobwas/ws"
	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/utils/conversion"
)

type Runner struct {
	BinaryPath                 string
	WorkingDir                 string
	BaseEnv                    []string
	ExtraArgs                  []string
	DisableAutoUpdate          bool
	AllowLocalFileAccess       bool
	InteractionsPollDuration   string
	InteractionsCooldownPeriod string
}

type RunnerOption func(*Runner)

func NewRunner(options ...RunnerOption) *Runner {
	runner := &Runner{
		BinaryPath:                 "nuclei",
		BaseEnv:                    []string{"DISABLE_CLOUD_UPLOAD_WRN=true", "DISABLE_CLOUD_UPLOAD=true"},
		DisableAutoUpdate:          true,
		AllowLocalFileAccess:       true,
		InteractionsPollDuration:   "1",
		InteractionsCooldownPeriod: "10",
	}
	for _, option := range options {
		option(runner)
	}

	return runner
}

func (r *Runner) Clone(options ...RunnerOption) *Runner {
	clone := &Runner{
		BinaryPath:                 r.BinaryPath,
		WorkingDir:                 r.WorkingDir,
		BaseEnv:                    append([]string{}, r.BaseEnv...),
		ExtraArgs:                  append([]string{}, r.ExtraArgs...),
		DisableAutoUpdate:          r.DisableAutoUpdate,
		AllowLocalFileAccess:       r.AllowLocalFileAccess,
		InteractionsPollDuration:   r.InteractionsPollDuration,
		InteractionsCooldownPeriod: r.InteractionsCooldownPeriod,
	}
	for _, option := range options {
		option(clone)
	}

	return clone
}

func WithBinaryPath(path string) RunnerOption {
	return func(r *Runner) {
		if trimmed := strings.TrimSpace(path); trimmed != "" {
			r.BinaryPath = trimmed
		}
	}
}

func WithWorkingDir(dir string) RunnerOption {
	return func(r *Runner) {
		r.WorkingDir = strings.TrimSpace(dir)
	}
}

func WithBaseEnv(env ...string) RunnerOption {
	return func(r *Runner) {
		r.BaseEnv = append(r.BaseEnv, env...)
	}
}

func WithExtraArgs(args ...string) RunnerOption {
	return func(r *Runner) {
		r.ExtraArgs = append([]string{}, args...)
	}
}

var defaultRunner = NewRunner()

func DefaultRunner() *Runner {
	return defaultRunner.Clone()
}

func SetDefaultRunner(runner *Runner) {
	if runner == nil {
		defaultRunner = NewRunner()

		return
	}

	defaultRunner = runner.Clone()
}

func (r *Runner) command(binaryPath string, args ...string) *exec.Cmd {
	resolvedBinary := strings.TrimSpace(binaryPath)
	if resolvedBinary == "" {
		resolvedBinary = strings.TrimSpace(r.BinaryPath)
	}

	if resolvedBinary == "" {
		resolvedBinary = "nuclei"
	}

	cmd := exec.Command(resolvedBinary, args...)
	if r.WorkingDir != "" {
		cmd.Dir = r.WorkingDir
	}

	return cmd
}

func (r *Runner) buildArgs(args []string, pollDuration string) []string {
	builtArgs := append([]string{}, args...)

	builtArgs = append(builtArgs, r.ExtraArgs...)

	if r.DisableAutoUpdate {
		builtArgs = append(builtArgs, "-duc")
	}

	if pollDuration != "" {
		builtArgs = append(builtArgs, "-interactions-poll-duration", pollDuration)
	}

	if r.InteractionsCooldownPeriod != "" {
		builtArgs = append(builtArgs, "-interactions-cooldown-period", r.InteractionsCooldownPeriod)
	}

	if r.AllowLocalFileAccess {
		builtArgs = append(builtArgs, "-allow-local-file-access")
	}

	return builtArgs
}

func (r *Runner) buildEnv(extra []string) []string {
	merged := append([]string{}, os.Environ()...)
	merged = append(merged, r.BaseEnv...)
	merged = append(merged, extra...)

	return merged
}

func (r *Runner) parseResults(output []byte, err error) ([]string, error) {
	data := strings.TrimSpace(conversion.String(output))
	parts := make([]string, 0)

	for item := range strings.SplitSeq(data, "\n") {
		if item != "" {
			parts = append(parts, item)
		}
	}

	if (data == "" || len(parts) == 0) && err != nil {
		return nil, fmt.Errorf("%w: %v", err, data)
	}

	return parts, nil
}

func (r *Runner) TemplateResults(template, url string, debug bool, extra ...string) ([]string, error) {
	args := []string{"-t", template, "-target", url}
	args = append(args, extra...)

	return r.BareResults(debug, nil, args...)
}

func (r *Runner) WorkflowResults(workflow, url string, debug bool, extra ...string) ([]string, error) {
	args := []string{"-w", workflow, "-target", url}
	args = append(args, extra...)

	return r.BareResults(debug, nil, args...)
}

func (r *Runner) BareResults(debug bool, env []string, args ...string) ([]string, error) {
	cmd := r.command("")
	cmd.Args = append(cmd.Args[:1], r.buildArgs(args, r.InteractionsPollDuration)...)

	cmd.Env = r.buildEnv(env)

	if debug {
		cmd.Args = append(cmd.Args, "-debug")
		cmd.Stderr = os.Stderr
		fmt.Println(cmd.String())
	} else {
		cmd.Args = append(cmd.Args, "-silent")
	}

	output, err := cmd.Output()
	if debug && len(output) > 0 {
		fmt.Println(strings.TrimSpace(conversion.String(output)))
	}

	return r.parseResults(output, err)
}

func (r *Runner) ArgsResults(debug bool, args ...string) ([]string, error) {
	cmd := r.command("", append(append([]string{}, args...), r.ExtraArgs...)...)

	cmd.Env = r.buildEnv(nil)

	if debug {
		cmd.Args = append(cmd.Args, "-debug")
		cmd.Stderr = os.Stderr
		fmt.Println(cmd.String())
	} else {
		cmd.Args = append(cmd.Args, "-silent")
	}

	output, err := cmd.Output()
	if debug && len(output) > 0 {
		fmt.Println(strings.TrimSpace(conversion.String(output)))
	}

	return r.parseResults(output, err)
}

func (r *Runner) ArgsErrors(debug bool, env []string, args ...string) ([]string, error) {
	cmd := r.command("")
	cmd.Args = append(cmd.Args[:1], r.buildArgs(args, r.InteractionsPollDuration)...)
	cmd.Args = append(cmd.Args, "-nc")
	cmd.Env = r.buildEnv(env)

	output, err := cmd.CombinedOutput()
	if debug && len(output) > 0 {
		fmt.Println(string(output))
	}

	results := []string{}

	for line := range strings.SplitSeq(strings.TrimSpace(conversion.String(output)), "\n") {
		trimmed := strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(trimmed, "[ERR]"), strings.HasPrefix(trimmed, "[WRN]"), strings.HasPrefix(trimmed, "[FTL]"):
			results = append(results, trimmed)
		}
	}

	return results, err
}

func (r *Runner) ArgsResultsWithEnv(debug bool, env []string, args ...string) ([]string, error) {
	clone := r.Clone()
	clone.InteractionsPollDuration = "5"

	return clone.BareResults(debug, env, args...)
}

func (r *Runner) LoadedTemplates(binaryPath string, debug bool, args []string) (string, error) {
	cmd := r.command(binaryPath, append(append([]string{}, args...), r.ExtraArgs...)...)

	cmd.Env = r.buildEnv(nil)

	if r.DisableAutoUpdate {
		cmd.Args = append(cmd.Args, "-duc")
	}

	if debug {
		cmd.Args = append(cmd.Args, "-debug")
		fmt.Println(cmd.String())
	}

	data, err := cmd.CombinedOutput()
	if debug && len(data) > 0 {
		fmt.Println(string(data))
	}

	if err != nil {
		return "", err
	}

	matches := templateLoaded.FindAllStringSubmatch(string(data), -1)
	if len(matches) == 0 {
		return "", errors.New("no matches found")
	}

	return matches[0][1], nil
}

func (r *Runner) CombinedOutput(debug bool, args []string) (string, error) {
	builtArgs := r.buildArgs(args, r.InteractionsPollDuration)
	cmd := r.command("", builtArgs...)

	cmd.Env = r.buildEnv(nil)

	if debug {
		cmd.Args = append(cmd.Args, "-debug")
		fmt.Println(cmd.String())
	}

	data, err := cmd.CombinedOutput()
	if debug && len(data) > 0 {
		fmt.Println(string(data))
	}

	if err != nil {
		return "", err
	}

	return string(data), nil
}

// RunNucleiTemplateAndGetResults returns a list of results for a template.
func RunNucleiTemplateAndGetResults(template, url string, debug bool, extra ...string) ([]string, error) {
	return defaultRunner.TemplateResults(template, url, debug, extra...)
}

// RunNucleiWorkflowAndGetResults returns a list of results for a workflow.
func RunNucleiWorkflowAndGetResults(template, url string, debug bool, extra ...string) ([]string, error) {
	return defaultRunner.WorkflowResults(template, url, debug, extra...)
}

func RunNucleiAndGetResults(isTemplate bool, template, url string, debug bool, extra ...string) ([]string, error) {
	if isTemplate {
		return defaultRunner.TemplateResults(template, url, debug, extra...)
	} else {
		return defaultRunner.WorkflowResults(template, url, debug, extra...)
	}
}

func RunNucleiBareArgsAndGetResults(debug bool, env []string, extra ...string) ([]string, error) {
	return defaultRunner.BareResults(debug, env, extra...)
}

// RunNucleiWithArgsAndGetResults returns result,and runtime errors.
func RunNucleiWithArgsAndGetResults(debug bool, args ...string) ([]string, error) {
	return defaultRunner.ArgsResults(debug, args...)
}

// RunNucleiArgsAndGetErrors returns a list of errors in nuclei output (ERR,WRN,FTL).
func RunNucleiArgsAndGetErrors(debug bool, env []string, extra ...string) ([]string, error) {
	return defaultRunner.ArgsErrors(debug, env, extra...)
}

// RunNucleiArgsWithEnvAndGetResults returns a list of results in nuclei output (ERR,WRN,FTL).
func RunNucleiArgsWithEnvAndGetResults(debug bool, env []string, extra ...string) ([]string, error) {
	return defaultRunner.ArgsResultsWithEnv(debug, env, extra...)
}

var templateLoaded = regexp.MustCompile(`(?:Templates|Workflows) loaded[^:]*: (\d+)`)

// RunNucleiBinaryAndGetLoadedTemplates returns a list of results for a template.
func RunNucleiBinaryAndGetLoadedTemplates(nucleiBinary string, debug bool, args []string) (string, error) {
	return defaultRunner.LoadedTemplates(nucleiBinary, debug, args)
}

func RunNucleiBinaryAndGetCombinedOutput(debug bool, args []string) (string, error) {
	return defaultRunner.CombinedOutput(debug, args)
}

// TestCase is a single integration test case.
type TestCase interface {
	// Execute executes a test case and returns any errors if occurred
	Execute(filePath string) error
}

// TCPServer creates a new tcp server that returns a response.
type TCPServer struct {
	URL      string
	listener net.Listener
}

// keys taken from https://pascal.bach.ch/2015/12/17/from-tcp-to-tls-in-go/
const serverKey = `-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBJazGwuqgOLsCMr7P56w26JBEHQokiuAy2iCQfCnmOWm7S9FveQ/DP
qB69zvUPs26gBwYFK4EEACKhZANiAARehvy96ygCAsJ6iQvthzl/Nvq4P3c4MGyx
UMLMe0L10OCxeCl5ZY2CuFf8UnBgV1u414U4+yjIrS57w1/3utBKC9TVRGj+Vcls
2NZ4+8Jh6/M/Jf/Mpd8QyIy0WesEUM4=
-----END EC PRIVATE KEY-----
`

const serverCert = `-----BEGIN CERTIFICATE-----
MIICJDCCAakCCQDFa0/D9jJw6DAKBggqhkjOPQQDAjB7MQswCQYDVQQGEwJVUzEP
MA0GA1UECAwGcGRsYW5kMQ8wDQYDVQQHDAZwZGNpdHkxCzAJBgNVBAoMAnBkMQsw
CQYDVQQLDAJwZDELMAkGA1UEAwwCcGQxIzAhBgkqhkiG9w0BCQEWFGFueXRoaW5n
QGFueXRoaW5nLnBkMB4XDTIyMDEyNzIyMDUwNFoXDTMyMDEyNTIyMDUwNFowezEL
MAkGA1UEBhMCVVMxDzANBgNVBAgMBnBkbGFuZDEPMA0GA1UEBwwGcGRjaXR5MQsw
CQYDVQQKDAJwZDELMAkGA1UECwwCcGQxCzAJBgNVBAMMAnBkMSMwIQYJKoZIhvcN
AQkBFhRhbnl0aGluZ0Bhbnl0aGluZy5wZDB2MBAGByqGSM49AgEGBSuBBAAiA2IA
BF6G/L3rKAICwnqJC+2HOX82+rg/dzgwbLFQwsx7QvXQ4LF4KXlljYK4V/xScGBX
W7jXhTj7KMitLnvDX/e60EoL1NVEaP5VyWzY1nj7wmHr8z8l/8yl3xDIjLRZ6wRQ
zjAKBggqhkjOPQQDAgNpADBmAjEAgxGPbjRlhz+1Scmr6RU9VbzVJWN8KCsTTpx7
pqfmKpJ29UYReZN+fm/6fc5vkv1rAjEAkTuTf8ARSn1UiKlCTTDQVtCoRcMVLQQp
TCxxGzcAlUAAJE6+SJpY7fPRe+n2EvPS
-----END CERTIFICATE-----
`

// NewTCPServer creates a new TCP server from a handler.
func NewTCPServer(tlsConfig *tls.Config, port int, handler func(conn net.Conn)) *TCPServer {
	server := &TCPServer{}

	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		panic(err)
	}

	server.URL = l.Addr().String()
	server.listener = l

	if tlsConfig != nil {
		cer, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
		if err != nil {
			panic(err)
		}

		tlsConfig.Certificates = []tls.Certificate{cer}
	}

	go func() {
		for {
			// Listen for an incoming connection.
			conn, err := l.Accept()
			if err != nil {
				continue
			}
			// Handle connections in a new goroutine.
			if tlsConfig != nil {
				connTls := tls.Server(conn, tlsConfig)
				go handler(connTls)
			} else {
				go handler(conn)
			}
		}
	}()

	return server
}

// Close closes the TCP server.
func (s *TCPServer) Close() {
	_ = s.listener.Close()
}

// NewWebsocketServer creates a new websocket server from a handler.
func NewWebsocketServer(path string, handler func(conn net.Conn), originValidate func(origin string) bool, port ...int) *httptest.Server {
	handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if value := r.Header.Get("Origin"); value != "" && !originValidate(value) {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}

		go func() {
			defer func() {
				_ = conn.Close()
			}()

			handler(conn)
		}()
	})

	if path != "" {
		router := httprouter.New()
		router.HandlerFunc("*", "/test", handlerFunc)

		return httptest.NewServer(router)
	}

	return httptest.NewServer(handlerFunc)
}
