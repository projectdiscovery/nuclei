package templates

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
	"github.com/stretchr/testify/require"
)

func TestClusterTemplates(t *testing.T) {
	tests := []struct {
		name      string
		templates []*Template
		expected  [][]*Template
	}{
		{
			name: "http-cluster-get",
			templates: []*Template{
				{Path: "first.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}"}}}},
				{Path: "second.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}"}}}},
			},
			expected: [][]*Template{{
				{RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}"}}}},
				{RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}"}}}},
			}},
		},
		{
			name: "no-http-cluster",
			templates: []*Template{
				{Path: "first.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}/random"}}}},
				{Path: "second.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}/another"}}}},
			},
			expected: [][]*Template{
				{{RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}/random"}}}}},
				{{RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}/another"}}}}},
			},
		},
		{
			name: "dns-cluster",
			templates: []*Template{
				{Path: "first.yaml", RequestsDNS: []*dns.Request{{Name: "{{Hostname}}"}}},
				{Path: "second.yaml", RequestsDNS: []*dns.Request{{Name: "{{Hostname}}"}}},
			},
			expected: [][]*Template{{
				{RequestsDNS: []*dns.Request{{Name: "{{Hostname}}"}}},
				{RequestsDNS: []*dns.Request{{Name: "{{Hostname}}"}}},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			returned := Cluster(test.templates)
			require.ElementsMatch(t, returned, test.expected, "could not get cluster results")
		})
	}
}
