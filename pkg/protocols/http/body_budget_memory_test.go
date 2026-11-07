//go:build !race

package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/httpbody"
)

// Threads and pipeline build bodies ahead of the send. Built bodies must stay
// within the budget while the server holds the first request.
func TestRequestBodyBudgetBoundsBodiesBuiltAhead(t *testing.T) {
	const bodySize = 8 << 20
	const payloads = 12

	for _, mode := range []string{"threads", "pipeline"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "pipeline" {
				t.Skip("needs projectdiscovery/rawhttp#551: the pipeline client hangs after 10s idle")
			}
			arrived := make(chan struct{}, payloads)
			unblock := make(chan struct{})
			var received atomic.Int32
			// net/http drops pipelined connections with large bodies, so serve
			// Content-Length framed requests in order by hand.
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer func() { _ = listener.Close() }()
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					go func() {
						defer func() { _ = conn.Close() }()
						reader := bufio.NewReader(conn)
						for {
							req, err := http.ReadRequest(reader)
							if err != nil {
								return
							}
							_, _ = io.Copy(io.Discard, req.Body)
							received.Add(1)
							arrived <- struct{}{}
							<-unblock
							if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
								return
							}
						}
					}()
				}
			}()
			target := "http://" + listener.Addr().String()

			options := testutils.DefaultOptions.Copy()
			testutils.Init(options)

			values := make([]string, payloads)
			for i := range values {
				values[i] = fmt.Sprint(i)
			}
			request := &Request{
				ID:       "body-budget-" + mode,
				Payloads: map[string]interface{}{"v": values},
			}
			body := `{{repeat("A", 8388608)}}`
			if mode == "threads" {
				request.Threads = 8
				request.Path = []string{"{{BaseURL}}/?v={{v}}"}
				request.Method = HTTPMethodTypeHolder{MethodType: HTTPPost}
				request.Body = body
			} else {
				request.Pipeline = true
				request.PipelineConcurrentConnections = 1
				request.PipelineRequestsPerConnection = payloads
				request.Raw = []string{"POST /?v={{v}} HTTP/1.1\nHost: {{Hostname}}\nContent-Length: 8388608\n\n" + body}
			}
			executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
				ID:   request.ID,
				Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
			})
			executerOpts.RequestBodyBudget = httpbody.NewBudget(bodySize)
			require.NoError(t, request.Compile(executerOpts))

			var before runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)

			done := make(chan error, 1)
			go func() {
				done <- request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), target), make(output.InternalEvent), make(output.InternalEvent), func(*output.InternalWrappedEvent) {})
			}()
			<-arrived
			time.Sleep(300 * time.Millisecond)
			var held runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&held)
			close(unblock)
			require.NoError(t, <-done)

			grown := int64(held.HeapAlloc) - int64(before.HeapAlloc)
			t.Logf("heap held: %d MB", grown>>20)
			require.Less(t, grown, int64(4*bodySize), "bodies built ahead of the send must stay within the budget")
			require.EqualValues(t, payloads, received.Load())
		})
	}
}
