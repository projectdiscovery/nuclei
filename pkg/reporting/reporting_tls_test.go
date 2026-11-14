package reporting_test

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/es"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/splunk"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/gitea"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/github"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/gitlab"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/jira"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// connectProxy tunnels every CONNECT to target, whatever host the client asked
// for, so no name is resolved and nothing leaves 127.0.0.1.
func connectProxy(t *testing.T, target string) *httptest.Server {
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "connect only", http.StatusMethodNotAllowed)
			return
		}
		up, err := net.Dial("tcp", target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = up.Close()
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
		go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
	}))
	t.Cleanup(p.Close)
	return p
}

// With -pi and a proxy, the runner gives reporting the scan client, which skips
// TLS verification. No tracker or exporter may send its secret to a server with
// an untrusted certificate.
func TestNewVerifiesTLSWithScanClient(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	proxy := connectProxy(t, srv.Listener.Addr().String())

	opts := types.DefaultOptions()
	opts.SetExecutionID("reporting-tls-test")
	opts.ProxyInternal = true
	opts.AliveHttpProxy = proxy.URL
	require.NoError(t, protocolstate.Init(opts))
	t.Cleanup(func() { protocolstate.Close(opts.ExecutionId) })
	scanClient, err := httpclientpool.Get(opts, &httpclientpool.Configuration{}, "")
	require.NoError(t, err)

	event := &output.ResultEvent{
		TemplateID: "test-template",
		Host:       "https://target.example",
		Matched:    "https://target.example/",
		Info:       model.Info{Name: "test", SeverityHolder: severity.Holder{Severity: severity.High}},
	}
	configs := map[string]*reporting.Options{
		"github":        {GitHub: &github.Options{BaseURL: "https://github.victim.example/", Username: "u", Owner: "o", ProjectName: "r", Token: "test-token"}},
		"gitlab":        {GitLab: &gitlab.Options{BaseURL: "https://gitlab.victim.example/", Username: "u", Token: "test-token", ProjectName: "1"}},
		"gitea":         {Gitea: &gitea.Options{BaseURL: "https://gitea.victim.example/", Token: "test-token", ProjectOwner: "o", ProjectName: "r"}},
		"jira":          {Jira: &jira.Options{Cloud: true, URL: "https://jira.victim.example", AccountID: "a", Email: "u@victim.example", Token: "test-token", ProjectName: "P", IssueType: "Bug"}},
		"elasticsearch": {ElasticsearchExporter: &es.Options{Host: "es.victim.example", Port: 443, SSL: true, Username: "u", Password: "test-password", IndexName: "n"}},
		"splunk":        {SplunkExporter: &splunk.Options{Host: "splunk.victim.example", Port: 443, SSL: true, Token: "test-token", IndexName: "n"}},
	}
	for name, ro := range configs {
		ro.HttpClient = scanClient
		ro.ExecutionId = opts.ExecutionId
		client, err := reporting.New(ro, "", true)
		if err == nil {
			_ = client.CreateIssue(event)
			client.Close()
		}
		require.Zero(t, hits.Load(), "%s sent a request to a server with an untrusted certificate", name)
	}
}
