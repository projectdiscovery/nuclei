package templates

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/code"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/file"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/javascript"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/network"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/ssl"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/websocket"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/whois"
	"github.com/stretchr/testify/require"
)

func TestAssignRequestOutputIDsCoversEveryProtocol(t *testing.T) {
	template := &Template{
		RequestsDNS:        []*dns.Request{{}},
		RequestsFile:       []*file.Request{{}},
		RequestsNetwork:    []*network.Request{{}},
		RequestsHTTP:       []*http.Request{{}},
		RequestsHeadless:   []*headless.Request{{}},
		RequestsSSL:        []*ssl.Request{{}, {}, {}, {}},
		RequestsWebsocket:  []*websocket.Request{{}},
		RequestsWHOIS:      []*whois.Request{{}},
		RequestsCode:       []*code.Request{{}},
		RequestsJavascript: []*javascript.Request{{ID: "explicit-js"}, {}},
	}

	template.assignRequestOutputIDs()

	require.Equal(t, "dns_1", template.RequestsDNS[0].RequestID)
	require.Equal(t, "file_1", template.RequestsFile[0].RequestID)
	require.Equal(t, "tcp_1", template.RequestsNetwork[0].RequestID)
	require.Equal(t, "http_1", template.RequestsHTTP[0].RequestID)
	require.Equal(t, "headless_1", template.RequestsHeadless[0].RequestID)
	require.Equal(t, "websocket_1", template.RequestsWebsocket[0].RequestID)
	require.Equal(t, "whois_1", template.RequestsWHOIS[0].RequestID)
	require.Equal(t, "code_1", template.RequestsCode[0].RequestID)
	for i, want := range []string{"ssl_1", "ssl_2", "ssl_3", "ssl_4"} {
		require.Equal(t, want, template.RequestsSSL[i].RequestID)
	}
	require.Equal(t, "explicit-js", template.RequestsJavascript[0].RequestID)
	require.Equal(t, "javascript_2", template.RequestsJavascript[1].RequestID)

	for _, request := range template.RequestsSSL {
		require.Empty(t, request.ID, "output identity must not rewrite the template request id")
	}
}

func TestAssignRequestOutputIDsIsRepeatable(t *testing.T) {
	template := &Template{RequestsHTTP: []*http.Request{{ID: "login"}, {}}}

	template.assignRequestOutputIDs()
	first := []string{template.RequestsHTTP[0].RequestID, template.RequestsHTTP[1].RequestID}
	template.assignRequestOutputIDs()

	require.Equal(t, []string{"login", "http_2"}, first)
	require.Equal(t, first, []string{template.RequestsHTTP[0].RequestID, template.RequestsHTTP[1].RequestID})
}
