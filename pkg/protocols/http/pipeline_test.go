package http

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

// servePipelined answers every request on a kept-alive connection with the
// response that respond returns for its request line. Cleanup closes the
// connections, so the pipeline client goroutines stop with the test.
func servePipelined(t *testing.T, respond func(method, path string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var (
		mu    sync.Mutex
		conns []net.Conn
		wg    sync.WaitGroup
	)
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				reader := textproto.NewReader(bufio.NewReader(conn))
				for {
					line, err := reader.ReadLine()
					if err != nil {
						return
					}
					if _, err := reader.ReadMIMEHeader(); err != nil {
						return
					}
					parts := strings.Fields(line)
					if len(parts) < 2 {
						return
					}
					if _, err := conn.Write([]byte(respond(parts[0], parts[1]))); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return "http://" + ln.Addr().String()
}

type pipelinedResult struct {
	status int
	body   string
}

// runPipelined sends the raw requests with a pipeline template and returns
// the status and body of every response.
func runPipelined(t *testing.T, target string, raw []string) []pipelinedResult {
	t.Helper()
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	request := &Request{
		ID:       "pipeline-bodyless",
		Raw:      raw,
		Pipeline: true,
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Type:   matchers.MatcherTypeHolder{MatcherType: matchers.StatusMatcher},
				Status: []int{200, 204, 304},
			}},
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOpts))

	var (
		mu      sync.Mutex
		results []pipelinedResult
	)
	err := request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), target), make(output.InternalEvent), make(output.InternalEvent), func(event *output.InternalWrappedEvent) {
		if event.OperatorsResult == nil || !event.OperatorsResult.Matched {
			return
		}
		status, _ := event.InternalEvent["status_code"].(int)
		body, _ := event.InternalEvent["body"].(string)
		mu.Lock()
		results = append(results, pipelinedResult{status: status, body: body})
		mu.Unlock()
	})
	require.NoError(t, err)
	return results
}

func TestPipelinedNoContentResponse(t *testing.T) {
	target := servePipelined(t, func(_, _ string) string {
		return "HTTP/1.1 204 No Content\r\nX-Pipe: yes\r\n\r\n"
	})
	start := time.Now()
	results := runPipelined(t, target, []string{
		"GET /a HTTP/1.1\nHost: {{Hostname}}\n\n",
		"GET /b HTTP/1.1\nHost: {{Hostname}}\n\n",
	})
	require.Len(t, results, 2, "every pipelined 204 must match")
	for _, result := range results {
		require.Equal(t, 204, result.status)
	}
	require.Less(t, time.Since(start), 3*time.Second, "a 204 has no body, so reading it must not wait for the read timeout")
}

// TestPipelinedBodylessWithContentLength checks that a bodyless response with
// a Content-Length does not consume the bytes of the next pipelined response.
func TestPipelinedBodylessWithContentLength(t *testing.T) {
	const next = "hello"
	tests := []struct {
		name     string
		first    string
		bodyless string
		status   int
	}{
		{
			name:     "HEAD",
			first:    "HEAD /a HTTP/1.1\nHost: {{Hostname}}\n\n",
			bodyless: fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(next)),
			status:   200,
		},
		{
			name:     "304",
			first:    "GET /a HTTP/1.1\nHost: {{Hostname}}\n\n",
			bodyless: fmt.Sprintf("HTTP/1.1 304 Not Modified\r\nContent-Length: %d\r\n\r\n", len(next)),
			status:   304,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := servePipelined(t, func(_, path string) string {
				if path == "/a" {
					return tt.bodyless
				}
				return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(next), next)
			})
			start := time.Now()
			results := runPipelined(t, target, []string{
				tt.first,
				"GET /b HTTP/1.1\nHost: {{Hostname}}\n\n",
			})
			require.Len(t, results, 2, "both pipelined responses must match")
			var bodyless, normal int
			for _, result := range results {
				switch {
				case result.status == tt.status && result.body == "":
					bodyless++
				case result.status == 200 && result.body == next:
					normal++
				default:
					t.Fatalf("unexpected response: status %d body %q", result.status, result.body)
				}
			}
			require.Equal(t, 1, bodyless, "the bodyless response must have an empty body")
			require.Equal(t, 1, normal, "the next response must keep its body")
			require.Less(t, time.Since(start), 3*time.Second, "reading the responses must not wait for the read timeout")
		})
	}
}
