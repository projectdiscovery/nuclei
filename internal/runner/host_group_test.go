package runner

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/network"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/stretchr/testify/require"
)

func TestHostGroupKey(t *testing.T) {
	// Lexicographic sort: "443" < "80".
	require.Equal(t, "http|443,80", hostGroupKey([]string{"443", "80"}, true))
	require.Equal(t, "nohttp|22", hostGroupKey([]string{"22"}, false))
	require.Equal(t, "nohttp|-", hostGroupKey(nil, false))
}

func TestTemplatesForHostGroup(t *testing.T) {
	web := &templates.Template{
		ID:           "web",
		RequestsHTTP: []*http.Request{{}},
	}
	ftp := &templates.Template{
		ID: "ftp",
		RequestsNetwork: []*network.Request{{
			Port: "21",
		}},
	}
	ssh := &templates.Template{
		ID: "ssh",
		RequestsNetwork: []*network.Request{{
			Port: "22",
		}},
	}
	all := []*templates.Template{web, ftp, ssh}

	webGroup := hostGroup{
		key:       "http|80,443",
		httpOK:    true,
		openPorts: map[string]struct{}{"80": {}, "443": {}},
	}
	got := templatesForHostGroup(all, webGroup)
	require.Len(t, got, 1)
	require.Equal(t, "web", got[0].ID)

	ftpGroup := hostGroup{
		key:       "nohttp|21",
		httpOK:    false,
		openPorts: map[string]struct{}{"21": {}},
	}
	got = templatesForHostGroup(all, ftpGroup)
	require.Len(t, got, 1)
	require.Equal(t, "ftp", got[0].ID)

	sshGroup := hostGroup{
		key:       "nohttp|22",
		httpOK:    false,
		openPorts: map[string]struct{}{"22": {}},
	}
	got = templatesForHostGroup(all, sshGroup)
	require.Len(t, got, 1)
	require.Equal(t, "ssh", got[0].ID)
}

func TestPartitionTemplates(t *testing.T) {
	web := &templates.Template{ID: "web", RequestsHTTP: []*http.Request{{}}}
	ftp := &templates.Template{ID: "ftp", RequestsNetwork: []*network.Request{{Port: "21"}}}
	self := &templates.Template{ID: "self", SelfContained: true}
	dynNet := &templates.Template{
		ID:              "dyn",
		RequestsNetwork: []*network.Request{{Port: ""}},
	}

	w, n, u, s := partitionTemplates([]*templates.Template{web, ftp, self, dynNet})
	require.Len(t, w, 1)
	require.Equal(t, "web", w[0].ID)
	require.Len(t, n, 1)
	require.Equal(t, "ftp", n[0].ID)
	require.Len(t, u, 1)
	require.Equal(t, "dyn", u[0].ID)
	require.Len(t, s, 1)
	require.Equal(t, "self", s[0].ID)
}

func TestEstimateGroupedVsBaseline(t *testing.T) {
	web := &templates.Template{ID: "web", RequestsHTTP: []*http.Request{{}}, TotalRequests: 1}
	ftp := &templates.Template{ID: "ftp", RequestsNetwork: []*network.Request{{Port: "21"}}, TotalRequests: 1}
	ssh := &templates.Template{ID: "ssh", RequestsNetwork: []*network.Request{{Port: "22"}}, TotalRequests: 1}
	all := []*templates.Template{web, ftp, ssh}

	groups := []hostGroup{
		{key: "http|80", httpOK: true, openPorts: map[string]struct{}{"80": {}}, hosts: metaInputs("h1", "h2")},
		{key: "nohttp|21", httpOK: false, openPorts: map[string]struct{}{"21": {}}, hosts: metaInputs("h3")},
		{key: "nohttp|22", httpOK: false, openPorts: map[string]struct{}{"22": {}}, hosts: metaInputs("h4")},
	}

	baseline, filtered := estimateGroupedExecutions(all, groups, 4)
	require.Equal(t, 12, baseline)
	// web*2 + ftp*1 + ssh*1 = 4
	require.Equal(t, 4, filtered)
	require.Equal(t, 8, baseline-filtered)
}

func TestHostReachabilityAllow(t *testing.T) {
	web := &templates.Template{ID: "web", RequestsHTTP: []*http.Request{{}}}
	ftp := &templates.Template{ID: "ftp", RequestsNetwork: []*network.Request{{Port: "21"}}}
	idx := &hostReachabilityIndex{byInput: map[string]hostReachability{
		"h1": {httpOK: true, openPorts: map[string]struct{}{"80": {}}},
		"h2": {httpOK: false, openPorts: map[string]struct{}{"21": {}}},
	}}
	require.True(t, idx.Allow(web, &contextargs.MetaInput{Input: "h1"}))
	require.False(t, idx.Allow(web, &contextargs.MetaInput{Input: "h2"}))
	require.False(t, idx.Allow(ftp, &contextargs.MetaInput{Input: "h1"}))
	require.True(t, idx.Allow(ftp, &contextargs.MetaInput{Input: "h2"}))
	require.True(t, idx.Allow(web, &contextargs.MetaInput{Input: "unknown"})) // lossless
}

func metaInputs(hosts ...string) []*contextargs.MetaInput {
	out := make([]*contextargs.MetaInput, 0, len(hosts))
	for _, h := range hosts {
		mi := contextargs.NewMetaInput()
		mi.Input = h
		out = append(out, mi)
	}
	return out
}
