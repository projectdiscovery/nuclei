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
	cmd.Args = append(cmd.Args, extra...)
	if debug {
		cmd.Args = append(cmd.Args, "-debug")
		cmd.Stderr = os.Stderr
		fmt.Println(cmd.String())
	} else {
		cmd.Args = append(cmd.Args, "-silent")
	}
	data, err := cmd.Output()
	if err != nil {
		return nil, err
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

var templateLoaded = regexp.MustCompile(`(?:Templates|Workflows) loaded[^:]*: (\d+)`)

// RunNucleiBinaryAndGetLoadedTemplates returns a list of results for a template
func RunNucleiBinaryAndGetLoadedTemplates(nucleiBinary string, debug bool, args []string) (string, error) {
	cmd := exec.Command(nucleiBinary, args...)
	if debug {
		cmd.Args = append(cmd.Args, "-debug")
		fmt.Println(cmd.String())
	}
	data, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	matches := templateLoaded.FindAllStringSubmatch(string(data), -1)
	if len(matches) == 0 {
		return "", errors.New("no matches found")
	}
	return matches[0][1], nil
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
func NewTCPServer(withTls bool, port int, handler func(conn net.Conn)) *TCPServer {
	server := &TCPServer{}

	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		panic(err)
	}
	server.URL = l.Addr().String()
	server.listener = l

	cer, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
	if err != nil {
		panic(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cer}}

	go func() {
		for {
			// Listen for an incoming connection.
			conn, err := l.Accept()
			if err != nil {
				continue
			}
			// Handle connections in a new goroutine.
			if withTls {
				connTls := tls.Server(conn, config)
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
