package templates

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
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
	// A cluster shares one event that holds the first template's variables and
	// extracted values, so a template with info placeholders runs on its own,
	// even next to one with the same variables.
	t.Run("no-cluster-with-info-placeholders", func(t *testing.T) {
		withVariables := func(path, product string) *Template {
			vars := variables.Variable{InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(1)}
			vars.Set("product", product)
			tp := &Template{
				Path:         path,
				RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}"}}},
				Info:         model.Info{Description: "{{product}} panel exposed"},
				Variables:    vars,
			}
			tp.Options = execOptions
			return tp
		}
		grafana := withVariables("grafana.yaml", "Grafana")
		alsoGrafana := withVariables("also-grafana.yaml", "Grafana")
		static := &Template{Path: "static.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}"}}}}
		alsoStatic := &Template{Path: "also-static.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}"}}}}
		static.Options = execOptions
		alsoStatic.Options = execOptions

		got := Cluster([]*Template{grafana, alsoGrafana, static, alsoStatic})
		require.ElementsMatch(t, [][]*Template{{grafana}, {alsoGrafana}, {static, alsoStatic}}, got)
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

// A cluster sends its first member's request for every member, so a race block
// would force its race_count on the others, or lose it to a plain one (#8280).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils state is shared
func TestClusterTemplatesRaceBlocksRunOnTheirOwn(t *testing.T) {
	execOptions := testutils.NewMockExecuterOptions(testutils.DefaultOptions, &testutils.TemplateInfo{
		ID:   "templateID",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	member := func(path string, race bool, count int) *Template {
		tmpl := &Template{Path: path, RequestsHTTP: []*http.Request{{
			Path:               []string{"{{BaseURL}}/same"},
			Race:               race,
			RaceNumberRequests: count,
		}}}
		tmpl.Options = execOptions

		return tmpl
	}
	plain, otherPlain := member("a-plain.yaml", false, 0), member("b-plain.yaml", false, 0)
	race, otherRace := member("c-race.yaml", true, 5), member("d-race.yaml", true, 3)
	// without race_count the block runs as any other
	raceOnly := member("e-race-only.yaml", true, 0)
	// clusters lists each cluster's template paths, so a failure prints names
	// and not whole templates
	clusters := func(members ...*Template) [][]string {
		clustered := Cluster(members)
		got := make([][]string, 0, len(clustered))

		for _, cluster := range clustered {
			paths := make([]string, 0, len(cluster))
			for _, tmpl := range cluster {
				paths = append(paths, tmpl.Path)
			}

			got = append(got, paths)
		}

		return got
	}

	require.ElementsMatch(t, [][]string{{race.Path}, {plain.Path}}, clusters(race, plain), "race with plain")
	require.ElementsMatch(t, [][]string{{race.Path}, {otherRace.Path}}, clusters(race, otherRace), "two race")
	require.ElementsMatch(t, [][]string{{plain.Path, otherPlain.Path}}, clusters(plain, otherPlain), "two plain")
	require.ElementsMatch(t, [][]string{{plain.Path, raceOnly.Path}}, clusters(plain, raceOnly), "no race_count")
}
