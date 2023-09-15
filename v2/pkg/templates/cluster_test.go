package templates

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
	"github.com/stretchr/testify/require"
)

func TestClusterTemplates(t *testing.T) {
	t.Run("http-cluster-get", func(t *testing.T) {
		tp1 := &Template{Path: "first.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}"}}}}
		tp2 := &Template{Path: "second.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}"}}}}
		tpls := []*Template{tp1, tp2}
		// cluster 0
		expected := []*Template{tp1, tp2}
		got := Cluster(tpls)[0]
		require.ElementsMatchf(t, expected, got, "different %v %v", len(expected), len(got))
	})
	t.Run("no-http-cluster", func(t *testing.T) {
		tp1 := &Template{Path: "first.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}/random"}}}}
		tp2 := &Template{Path: "second.yaml", RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}/another"}}}}
		tpls := []*Template{tp1, tp2}
		expected := [][]*Template{{tp1}, {tp2}}
		got := Cluster(tpls)
		require.ElementsMatch(t, expected, got)
	})
	t.Run("dns-cluster", func(t *testing.T) {
		tp1 := &Template{Path: "first.yaml", RequestsDNS: []*dns.Request{{Name: "{{Hostname}}"}}}
		tp2 := &Template{Path: "second.yaml", RequestsDNS: []*dns.Request{{Name: "{{Hostname}}"}}}
		tpls := []*Template{tp1, tp2}
		// cluster 0
		expected := []*Template{tp1, tp2}
		got := Cluster(tpls)[0]
		require.ElementsMatch(t, got, expected)
	})
}
