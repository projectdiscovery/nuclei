package catchall

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
)

// info mirrors a parsed template, whose tags are split and lowercased.
func info(tags ...string) model.Info {
	return model.Info{Tags: stringslice.StringSlice{Value: tags}}
}

func TestAppliesToPathClaims(t *testing.T) {
	ops := &operators.Operators{Matchers: []*matchers.Matcher{{Words: []string{"DB_PASSWORD"}}, {Status: []int{200}}}}
	require.True(t, Applies(info("exposure", "config"), ops))
}

func TestHostWideClaimsAreKept(t *testing.T) {
	ops := &operators.Operators{Matchers: []*matchers.Matcher{{Words: []string{"<title>Grafana</title>"}}}}
	require.False(t, Applies(info("tech", "discovery"), ops), "a single page app is still that app on its catch-all page")
	require.False(t, Applies(info("panel", "grafana"), ops))
}

func TestEvidenceOutsideTheBodyIsKept(t *testing.T) {
	cases := map[string]*matchers.Matcher{
		"header part":     {Part: "header", Words: []string{"Access-Control-Allow-Origin: https://evil.test"}},
		"interactsh part": {Part: "interactsh_protocol", Words: []string{"dns"}},
		"dsl on headers":  {DSL: []string{`contains(header, "X-Debug")`}},
		"dsl interactsh":  {DSL: []string{`contains(interactsh_protocol, "http")`}},
	}
	for name, matcher := range cases {
		ops := &operators.Operators{Matchers: []*matchers.Matcher{{Status: []int{200}}, matcher}}
		require.False(t, Applies(info("misconfig"), ops), name)
	}
}

func TestNoOperatorsNeverApplies(t *testing.T) {
	require.False(t, Applies(info("exposure"), nil))
}
