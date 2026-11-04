package whois

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/whois/rdapclientpool"
	"github.com/stretchr/testify/require"
)

func TestWhoisConcurrentRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = fmt.Fprint(w, `{
			"objectClassName": "domain",
			"ldhName": "example.com",
			"handle": "D123",
			"status": ["active"]
		}`)
	}))
	defer server.Close()

	options := testutils.DefaultOptions
	testutils.Init(options)
	_ = rdapclientpool.Init(options)

	request := &Request{
		Server: server.URL,
		Query:  "example.com",
	}
	execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "whois-concurrent-test",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	execOpts.IsMultiProtocol = true
	err := request.Compile(execOpts)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var gotResults bool
			err := request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), "example.com"), nil, nil, func(event *output.InternalWrappedEvent) {
				gotResults = true
			})
			_ = gotResults
			_ = err
		}()
	}
	wg.Wait()
}
