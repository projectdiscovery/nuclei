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
)

// ExtraArgs
var ExtraDebugArgs = []string{}

// RunNucleiTemplateAndGetResults returns a list of results for a template
func RunNucleiTemplateAndGetResults(template, url string, debug bool, extra ...string) ([]string, error) {
	return RunNucleiAndGetResults(true, template, url, debug, extra...)
}

// RunNucleiWorkflowAndGetResults returns a list of results for a workflow
func RunNucleiWorkflowAndGetResults(template, url string, debug bool, extra ...string) ([]string, error) {
	return RunNucleiAndGetResults(false, template, url, debug, extra...)
}

func RunNucleiAndGetResults(isTemplate bool, template, url string, debug bool, extra ...string) ([]string, error) {
	var templateOrWorkflowFlag string
	if isTemplate {
		templateOrWorkflowFlag = "-t"
	} else {
		templateOrWorkflowFlag = "-w"
	}

	return RunNucleiBareArgsAndGetResults(debug, append([]string{
		templateOrWorkflowFlag,
		template,
		"-target",
		url,
	}, extra...)...)
}

func RunNucleiBareArgsAndGetResults(debug bool, extra ...string) ([]string, error) {
	cmd := exec.Command("./nuclei")
	extra = append(extra, ExtraDebugArgs...)
	cmd.Args = append(cmd.Args, extra...)
	cmd.Args = append(cmd.Args, "-duc") // disable auto updates
	cmd.Args = append(cmd.Args, "-interactions-poll-duration", "1")
	cmd.Args = append(cmd.Args, "-interactions-cooldown-period", "10")
	cmd.Args = append(cmd.Args, "-allow-local-file-access")
	if debug {
		cmd.Args = append(cmd.Args, "-debug")
		cmd.Stderr = os.Stderr
		fmt.Println(cmd.String())
	} else {
		cmd.Args = append(cmd.Args, "-silent")
	}
	data, err := cmd.Output()
	if debug {
		fmt.Println(string(data))
	}
	if len(data) < 1 && err != nil {
		return nil, fmt.Errorf("%v: %v", err.Error(), string(data))
	}
	var parts []string
	items := strings.Split(string(data), "\n")
	for _, i := range items {
		if i != "" {
			parts = append(parts, i)
		}
	}
	return parts, nil
}

// RunNucleiArgsAndGetResults returns result,and runtime errors
func RunNucleiWithArgsAndGetResults(debug bool, args ...string) ([]string, error) {
	cmd := exec.Command("./nuclei", args...)
	if debug {
		cmd.Args = append(cmd.Args, "-debug")
		cmd.Stderr = os.Stderr
		fmt.Println(cmd.String())
	} else {
		cmd.Args = append(cmd.Args, "-silent")
	}
	data, err := cmd.Output()
	if debug {
		fmt.Println(string(data))
	}
	if len(data) < 1 && err != nil {
		return nil, fmt.Errorf("%v: %v", err.Error(), string(data))
	}
	var parts []string
	items := strings.Split(string(data), "\n")
	for _, i := range items {
		if i != "" {
			parts = append(parts, i)
		}
	}
	return parts, nil
}

// RunNucleiArgsAndGetErrors returns a list of errors in nuclei output (ERR,WRN,FTL)
func RunNucleiArgsAndGetErrors(debug bool, env []string, extra ...string) ([]string, error) {
	cmd := exec.Command("./nuclei")
	extra = append(extra, ExtraDebugArgs...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Args = append(cmd.Args, extra...)
	cmd.Args = append(cmd.Args, "-duc") // disable auto updates
	cmd.Args = append(cmd.Args, "-interactions-poll-duration", "1")
	cmd.Args = append(cmd.Args, "-interactions-cooldown-period", "10")
	cmd.Args = append(cmd.Args, "-allow-local-file-access")
	cmd.Args = append(cmd.Args, "-nc") // disable color
	data, err := cmd.CombinedOutput()
	if debug {
		fmt.Println(string(data))
	}
	results := []string{}
	for _, v := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(v)
		switch {
		case strings.HasPrefix(line, "[ERR]"):
			results = append(results, line)
		case strings.HasPrefix(line, "[WRN]"):
			results = append(results, line)
		case strings.HasPrefix(line, "[FTL]"):
			results = append(results, line)
		}
	}
	return results, err
}

var templateLoaded = regexp.MustCompile(`(?:Templates|Workflows) loaded[^:]*: (\d+)`)

// RunNucleiBinaryAndGetLoadedTemplates returns a list of results for a template
func RunNucleiBinaryAndGetLoadedTemplates(nucleiBinary string, debug bool, args []string) (string, error) {
	cmd := exec.Command(nucleiBinary, args...)
	cmd.Args = append(cmd.Args, "-duc") // disable auto updates
	if debug {
		cmd.Args = append(cmd.Args, "-debug")
		fmt.Println(cmd.String())
	}
	data, err := cmd.CombinedOutput()
	if debug {
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
func RunNucleiBinaryAndGetCombinedOutput(debug bool, args []string) (string, error) {
	args = append(args, "-interactions-cooldown-period", "10", "-interactions-poll-duration", "1")
	cmd := exec.Command("./nuclei", args...)
	if debug {
		cmd.Args = append(cmd.Args, "-debug")
		fmt.Println(cmd.String())
	}
	data, err := cmd.CombinedOutput()
	if debug {
		fmt.Println(string(data))
	}
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// TestCase is a single integration test case
type TestCase interface {
	// Execute executes a test case and returns any errors if occurred
	Execute(filePath string) error
}

// TCPServer creates a new tcp server that returns a response
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

// NewTCPServer creates a new TCP server from a handler
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

// Close closes the TCP server
func (s *TCPServer) Close() {
	s.listener.Close()
}

// NewWebsocketServer creates a new websocket server from a handler
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
			defer conn.Close()

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
