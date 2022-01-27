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
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHg+g2unjA5BkDtXSN9ShN7kbPlbCcqcYdDu+QeV8XWuoAoGCCqGSM49
AwEHoUQDQgAEcZpodWh3SEs5Hh3rrEiu1LZOYSaNIWO34MgRxvqwz1FMpLxNlx0G
cSqrxhPubawptX5MSr02ft32kfOlYbaF5Q==
-----END EC PRIVATE KEY-----
`

const serverCert = `-----BEGIN CERTIFICATE-----
MIIB+TCCAZ+gAwIBAgIJAL05LKXo6PrrMAoGCCqGSM49BAMCMFkxCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0xNTEyMDgxNDAxMTNa
Fw0yNTEyMDUxNDAxMTNaMFkxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0
YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxEjAQBgNVBAMM
CWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHGaaHVod0hLOR4d
66xIrtS2TmEmjSFjt+DIEcb6sM9RTKS8TZcdBnEqq8YT7m2sKbV+TEq9Nn7d9pHz
pWG2heWjUDBOMB0GA1UdDgQWBBR0fqrecDJ44D/fiYJiOeBzfoqEijAfBgNVHSME
GDAWgBR0fqrecDJ44D/fiYJiOeBzfoqEijAMBgNVHRMEBTADAQH/MAoGCCqGSM49
BAMCA0gAMEUCIEKzVMF3JqjQjuM2rX7Rx8hancI5KJhwfeKu1xbyR7XaAiEA2UT7
1xOP035EcraRmWPe7tO0LpXgMxlh2VItpc2uc2w=
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
