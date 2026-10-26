package http

import (
	"bufio"
	"context"
	"net"
	"net/textproto"
	"sync"
	"sync/atomic"
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

// servePipelined204 answers every request on a kept-alive connection with a
// 204 that has no Content-Length and no Transfer-Encoding. Cleanup closes the
// connections, so the pipeline client goroutines stop with the test.
func servePipelined204(t *testing.T) string {
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
					if _, err := reader.ReadLine(); err != nil {
						return
					}
					if _, err := reader.ReadMIMEHeader(); err != nil {
						return
					}
					if _, err := conn.Write([]byte("HTTP/1.1 204 No Content\r\nX-Pipe: yes\r\n\r\n")); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return "http://" + ln.Addr().String()
}

func TestPipelinedNoContentResponse(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	request := &Request{
		ID: "pipeline-204",
		Raw: []string{
			"GET /a HTTP/1.1\nHost: {{Hostname}}\n\n",
			"GET /b HTTP/1.1\nHost: {{Hostname}}\n\n",
		},
		Pipeline: true,
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Type:   matchers.MatcherTypeHolder{MatcherType: matchers.StatusMatcher},
				Status: []int{204},
			}},
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOpts))

	target := servePipelined204(t)
	var matched atomic.Int32
	start := time.Now()
	err := request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), target), make(output.InternalEvent), make(output.InternalEvent), func(event *output.InternalWrappedEvent) {
		if event.OperatorsResult != nil && event.OperatorsResult.Matched {
			matched.Add(1)
		}
	})
	require.NoError(t, err)
	require.Equal(t, int32(2), matched.Load(), "every pipelined 204 must match")
	require.Less(t, time.Since(start), 3*time.Second, "a 204 has no body, so reading it must not wait for the read timeout")
}
