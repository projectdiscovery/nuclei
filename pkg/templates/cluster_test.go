package templates

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/stretchr/testify/require"
)

func TestClusterTemplates(t *testing.T) {
	// state of whether template is flow or multiprotocol is stored in executerOptions i.e why we need to pass it
	execOptions := testutils.NewMockExecuterOptions(testutils.DefaultOptions, &testutils.TemplateInfo{
		ID:   "templateID",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	t.Run("http-cluster-get", func(t *testing.T) {
		tp1 := &Template{Path: "first.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}"}}}}
		tp2 := &Template{Path: "second.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}"}}}}
		tp1.Options = execOptions
		tp2.Options = execOptions
		tpls := []*Template{tp1, tp2}
		// cluster 0
		expected := []*Template{tp1, tp2}
		got := Cluster(tpls)[0]
		require.ElementsMatchf(t, expected, got, "different %v %v", len(expected), len(got))
	})
	t.Run("no-http-cluster", func(t *testing.T) {
		tp1 := &Template{Path: "first.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}/random"}}}}
		tp2 := &Template{Path: "second.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}/another"}}}}
		tp1.Options = execOptions
		tp2.Options = execOptions
		tpls := []*Template{tp1, tp2}
		expected := [][]*Template{{tp1}, {tp2}}
		got := Cluster(tpls)
		require.ElementsMatch(t, expected, got)
	})
	t.Run("dns-cluster", func(t *testing.T) {
		tp1 := &Template{Path: "first.yaml", RequestsDNS: []*dns.Request{{Name: "{{Hostname}}"}}}
		tp2 := &Template{Path: "second.yaml", RequestsDNS: []*dns.Request{{Name: "{{Hostname}}"}}}
		tp1.Options = execOptions
		tp2.Options = execOptions
		tpls := []*Template{tp1, tp2}
		// cluster 0
		expected := []*Template{tp1, tp2}
		got := Cluster(tpls)[0]
		require.ElementsMatch(t, got, expected)
	})
}

func TestClusterExecuterMatchesPerTargetFilters(t *testing.T) {
	cluster := &ClusterExecuter{
		operators: []*clusteredOperator{
			{
				templateID:   "apache-template",
				templatePath: "/templates/apache.yaml",
				templateInfo: model.Info{
					Tags:           stringslice.New([]string{"apache"}),
					SeverityHolder: severity.Holder{Severity: severity.High},
				},
				operator: &operators.Operators{},
			},
			{
				templateID:   "nginx-template",
				templatePath: "/templates/nginx.yaml",
				templateInfo: model.Info{
					Tags:           stringslice.New([]string{"nginx"}),
					SeverityHolder: severity.Holder{Severity: severity.Medium},
				},
				operator: &operators.Operators{},
			},
		},
	}

	apache := &contextargs.TargetFilter{}
	apache.Prepare([]string{"apache"}, nil, nil, nil, nil, false)
	require.True(t, cluster.MatchesTargetFilter(apache))
	require.True(t, operatorMatchesTargetFilter(cluster.operators[0], apache))
	require.False(t, operatorMatchesTargetFilter(cluster.operators[1], apache))

	none := &contextargs.TargetFilter{}
	none.Prepare([]string{"tomcat"}, nil, nil, nil, nil, false)
	require.False(t, cluster.MatchesTargetFilter(none))

	all := &contextargs.TargetFilter{}
	all.Prepare(nil, nil, nil, nil, nil, false)
	require.True(t, cluster.MatchesTargetFilter(all))
	require.True(t, operatorMatchesTargetFilter(cluster.operators[0], all))
	require.True(t, operatorMatchesTargetFilter(cluster.operators[1], all))
}
