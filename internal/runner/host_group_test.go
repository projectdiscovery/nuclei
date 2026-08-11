package runner

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input"
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
	redis := &templates.Template{ID: "redis", RequestsNetwork: []*network.Request{{Port: "6379"}}}
	idx := &hostReachabilityIndex{byInput: map[string]hostReachability{
		"h1":              {httpOK: true, openPorts: map[string]struct{}{"80": {}}},
		"h2":              {httpOK: false, openPorts: map[string]struct{}{"21": {}}},
		"127.0.0.1:19637": {httpOK: false, openPorts: map[string]struct{}{"19637": {}}, explicitPort: "19637"},
	}}
	require.True(t, idx.Allow(web, &contextargs.MetaInput{Input: "h1"}))
	require.False(t, idx.Allow(web, &contextargs.MetaInput{Input: "h2"}))
	require.False(t, idx.Allow(ftp, &contextargs.MetaInput{Input: "h1"}))
	require.True(t, idx.Allow(ftp, &contextargs.MetaInput{Input: "h2"}))
	require.True(t, idx.Allow(web, &contextargs.MetaInput{Input: "unknown"})) // lossless
	// Explicit host:port must allow network templates even when template default
	// port (6379) differs from the operator-specified port (19637).
	require.True(t, idx.Allow(redis, &contextargs.MetaInput{Input: "127.0.0.1:19637"}))
	require.False(t, idx.Allow(web, &contextargs.MetaInput{Input: "127.0.0.1:19637"}))
}

func TestTemplateAllowedOnHostUniversal(t *testing.T) {
	dnsish := &templates.Template{ID: "dns", RequestsDNS: nil} // no concrete network ports
	// force universal via empty network dynamic port
	dyn := &templates.Template{ID: "dyn", RequestsNetwork: []*network.Request{{Port: ""}}}
	require.True(t, templateAllowedOnHost(dyn, false, map[string]struct{}{}, ""))
	_ = dnsish
	self := &templates.Template{ID: "self", SelfContained: true}
	require.True(t, templateAllowedOnHost(self, false, nil, ""))
}

func TestTemplateAllowedOnHostExplicitPort(t *testing.T) {
	redis := &templates.Template{ID: "redis", RequestsNetwork: []*network.Request{{Port: "6379"}}}
	web := &templates.Template{ID: "web", RequestsHTTP: []*http.Request{{}}}
	open := map[string]struct{}{"19637": {}}
	require.True(t, templateAllowedOnHost(redis, false, open, "19637"))
	require.False(t, templateAllowedOnHost(redis, false, open, "")) // bare host: need 6379
	require.False(t, templateAllowedOnHost(web, false, open, "19637"))
	// Closed explicit port: openPorts empty => network templates denied.
	require.False(t, templateAllowedOnHost(redis, false, map[string]struct{}{}, "19637"))
}

func TestTemplatesForHostGroupExplicitPort(t *testing.T) {
	redis := &templates.Template{ID: "redis", RequestsNetwork: []*network.Request{{Port: "6379"}}}
	ftp := &templates.Template{ID: "ftp", RequestsNetwork: []*network.Request{{Port: "21"}}}
	web := &templates.Template{ID: "web", RequestsHTTP: []*http.Request{{}}}
	g := hostGroup{
		httpOK:       false,
		openPorts:    map[string]struct{}{"19637": {}},
		explicitPort: "19637",
	}
	got := templatesForHostGroup([]*templates.Template{redis, ftp, web}, g)
	require.Len(t, got, 2)
	ids := map[string]bool{got[0].ID: true, got[1].ID: true}
	require.True(t, ids["redis"] && ids["ftp"])
}

func TestCountReachabilityStats(t *testing.T) {
	web := &templates.Template{ID: "web", RequestsHTTP: []*http.Request{{}}}
	redis := &templates.Template{ID: "redis", RequestsNetwork: []*network.Request{{Port: "6379"}}}
	pg := &templates.Template{ID: "pg", RequestsNetwork: []*network.Request{{Port: "5432,5432"}}}
	dyn := &templates.Template{ID: "dyn", RequestsNetwork: []*network.Request{{Port: ""}}}
	concrete, ports := countReachabilityStats([]*templates.Template{web, redis, pg, dyn})
	require.Equal(t, 2, concrete)
	require.Equal(t, 2, ports) // 6379 + 5432
}

func TestResolveHTTPReachability(t *testing.T) {
	require.True(t, resolveHTTPReachability(&contextargs.MetaInput{Input: "http://web"}, nil, nil, nil))
	require.True(t, resolveHTTPReachability(&contextargs.MetaInput{Input: "https://web"}, nil, nil, nil))
	require.False(t, resolveHTTPReachability(&contextargs.MetaInput{Input: "redis1"}, map[string]struct{}{}, nil, nil))
	require.True(t, resolveHTTPReachability(&contextargs.MetaInput{Input: "host"}, map[string]struct{}{"80": {}}, nil, nil))
	require.True(t, resolveHTTPReachability(&contextargs.MetaInput{Input: "host"}, map[string]struct{}{"443": {}}, nil, nil))
}

func TestResolveHTTPReachabilitySkippedProbeFailOpen(t *testing.T) {
	// MultiFormat leaves an empty InputsHTTP map without probing — must not
	// force non-HTTP when open ports still suggest HTTP.
	helper := &input.Helper{InputsHTTPProbed: false}
	require.True(t, resolveHTTPReachability(&contextargs.MetaInput{Input: "host"}, map[string]struct{}{"80": {}}, helper, nil))
}

func TestTemplatesForHostGroupSkipsUniversal(t *testing.T) {
	web := &templates.Template{ID: "web", RequestsHTTP: []*http.Request{{}}}
	univ := &templates.Template{ID: "univ", RequestsNetwork: []*network.Request{{Port: ""}}}
	g := hostGroup{httpOK: true, openPorts: map[string]struct{}{"80": {}}}
	got := templatesForHostGroup([]*templates.Template{web, univ}, g)
	require.Len(t, got, 1)
	require.Equal(t, "web", got[0].ID)
}

func TestEstimateGroupedIncludesUniversalsOnce(t *testing.T) {
	web := &templates.Template{ID: "web", RequestsHTTP: []*http.Request{{}}, TotalRequests: 1}
	univ := &templates.Template{ID: "univ", RequestsNetwork: []*network.Request{{Port: ""}}, TotalRequests: 1}
	groups := []hostGroup{
		{httpOK: true, openPorts: map[string]struct{}{"80": {}}, hosts: metaInputs("h1")},
	}
	baseline, filtered := estimateGroupedExecutions([]*templates.Template{web, univ}, groups, 1)
	require.Equal(t, 2, baseline)
	// universal counted once for all hosts + web for http group
	require.Equal(t, 2, filtered)
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
