package filter

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

func TestTagBasedFilter(t *testing.T) {
	newDummyTemplate := func(id string, tags, authors []string, severityValue severity.Severity, protocolType types.ProtocolType) *templates.Template {
		dummyTemplate := &templates.Template{}
		if id != "" {
			dummyTemplate.ID = id
		}
		if len(tags) > 0 {
			dummyTemplate.Info.Tags = stringslice.StringSlice{Value: tags}
		}
		if len(authors) > 0 {
			dummyTemplate.Info.Authors = stringslice.StringSlice{Value: authors}
		}
		dummyTemplate.Info.SeverityHolder = severity.Holder{Severity: severityValue}
		switch protocolType {
		case types.DNSProtocol:
			dummyTemplate.RequestsDNS = []*dns.Request{{}}
		case types.HTTPProtocol:
			dummyTemplate.RequestsHTTP = []*http.Request{{}}
		}
		return dummyTemplate
	}

	filter, err := New(&Config{
		Tags: []string{"cves", "2021", "jira"},
	})
	require.Nil(t, err)

	t.Run("true", func(t *testing.T) {
		dummyTemplate := newDummyTemplate("", []string{"jira"}, []string{"pdteam"}, severity.Low, types.HTTPProtocol)
		matched, _ := filter.Match(dummyTemplate, nil)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("false", func(t *testing.T) {
		dummyTemplate := newDummyTemplate("", []string{"consul"}, []string{"pdteam"}, severity.Low, types.HTTPProtocol)
		matched, _ := filter.Match(dummyTemplate, nil)
		require.False(t, matched, "could not get correct match")
	})
	t.Run("match-extra-tags-positive", func(t *testing.T) {
		dummyTemplate := newDummyTemplate("", []string{"cves", "vuln"}, []string{"pdteam"}, severity.Low, types.HTTPProtocol)
		matched, _ := filter.Match(dummyTemplate, []string{"vuln"})
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-extra-tags-negative", func(t *testing.T) {
		dummyTemplate := newDummyTemplate("", []string{"cves"}, []string{"pdteam"}, severity.Low, types.HTTPProtocol)
		matched, _ := filter.Match(dummyTemplate, []string{"vuln"})
		require.False(t, matched, "could not get correct match")
	})

	t.Run("not-match-excludes", func(t *testing.T) {
		filter, err := New(&Config{
			ExcludeTags: []string{"dos"},
		})
		require.Nil(t, err)
		dummyTemplate := newDummyTemplate("", []string{"dos"}, []string{"pdteam"}, severity.Low, types.HTTPProtocol)
		matched, err := filter.Match(dummyTemplate, nil)
		require.False(t, matched, "could not get correct match")
		require.Equal(t, ErrExcluded, err, "could not get correct error")
	})
	t.Run("match-includes", func(t *testing.T) {
		filter, err := New(&Config{
			Tags:        []string{"cves", "fuzz"},
			ExcludeTags: []string{"dos", "fuzz"},
			IncludeTags: []string{"fuzz"},
		})
		require.Nil(t, err)
		dummyTemplate := newDummyTemplate("", []string{"fuzz"}, []string{"pdteam"}, severity.Low, types.HTTPProtocol)
		matched, err := filter.Match(dummyTemplate, nil)
		require.Nil(t, err, "could not get match")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-includes", func(t *testing.T) {
		filter, err := New(&Config{
			Tags:        []string{"fuzz"},
			ExcludeTags: []string{"fuzz"},
		})
		require.Nil(t, err)
		dummyTemplate := newDummyTemplate("", []string{"fuzz"}, []string{"pdteam"}, severity.Low, types.HTTPProtocol)
		matched, err := filter.Match(dummyTemplate, nil)
		require.Nil(t, err, "could not get match")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-author", func(t *testing.T) {
		filter, err := New(&Config{
			Authors: []string{"pdteam"},
		})
		require.Nil(t, err)
		dummyTemplate := newDummyTemplate("", []string{"fuzz"}, []string{"pdteam"}, severity.Low, types.HTTPProtocol)
		matched, _ := filter.Match(dummyTemplate, nil)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-severity", func(t *testing.T) {
		filter, err := New(&Config{
			Severities: severity.Severities{severity.High},
		})
		require.Nil(t, err)
		dummyTemplate := newDummyTemplate("", []string{"fuzz"}, []string{"pdteam"}, severity.High, types.HTTPProtocol)
		matched, _ := filter.Match(dummyTemplate, nil)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-id", func(t *testing.T) {
		filter, err := New(&Config{
			IncludeIds: []string{"cve-test"},
		})
		require.Nil(t, err)
		dummyTemplate := newDummyTemplate("cve-test", nil, nil, severity.Low, types.HTTPProtocol)
		matched, _ := filter.Match(dummyTemplate, nil)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-exclude-severity", func(t *testing.T) {
		filter, err := New(&Config{
			ExcludeSeverities: severity.Severities{severity.Low},
		})
		require.Nil(t, err)
		dummyTemplate := newDummyTemplate("", []string{"fuzz"}, []string{"pdteam"}, severity.High, types.HTTPProtocol)
		matched, _ := filter.Match(dummyTemplate, nil)
		require.True(t, matched, "could not get correct match")
		dummyTemplate = newDummyTemplate("", []string{"fuzz"}, []string{"pdteam"}, severity.Low, types.HTTPProtocol)
		matched, _ = filter.Match(dummyTemplate, nil)
		require.False(t, matched, "could not get correct match")
	})
	t.Run("match-exclude-with-tags", func(t *testing.T) {
		filter, err := New(&Config{
			Tags:        []string{"tag"},
			ExcludeTags: []string{"another"},
		})
		require.Nil(t, err)
		dummyTemplate := newDummyTemplate("", []string{"another"}, []string{"pdteam"}, severity.High, types.HTTPProtocol)
		matched, _ := filter.Match(dummyTemplate, nil)
		require.False(t, matched, "could not get correct match")
	})
	t.Run("match-conditions", func(t *testing.T) {
		filter, err := New(&Config{
			Authors:    []string{"pdteam"},
			Tags:       []string{"jira"},
			Severities: severity.Severities{severity.High},
		})
		require.Nil(t, err)

		dummyTemplate := newDummyTemplate("", []string{"jira", "cve"}, []string{"pdteam", "someOtherUser"}, severity.High, types.HTTPProtocol)
		matched, _ := filter.Match(dummyTemplate, nil)
		require.True(t, matched, "could not get correct match")
		dummyTemplate = newDummyTemplate("", []string{"jira"}, []string{"pdteam"}, severity.Low, types.HTTPProtocol)
		matched, _ = filter.Match(dummyTemplate, nil)
		require.False(t, matched, "could not get correct match")
		dummyTemplate = newDummyTemplate("", []string{"jira"}, []string{"pdteam"}, severity.Low, types.HTTPProtocol)
		matched, _ = filter.Match(dummyTemplate, nil)
		require.False(t, matched, "could not get correct match")
		dummyTemplate = newDummyTemplate("", []string{"consul"}, []string{"random"}, severity.Low, types.HTTPProtocol)
		matched, _ = filter.Match(dummyTemplate, nil)
		require.False(t, matched, "could not get correct match")
	})
	t.Run("match-type", func(t *testing.T) {
		filter, err := New(&Config{
			Protocols: []types.ProtocolType{types.HTTPProtocol},
		})
		require.Nil(t, err)

		dummyTemplate := newDummyTemplate("", []string{"fuzz"}, []string{"pdteam"}, severity.High, types.HTTPProtocol)
		matched, _ := filter.Match(dummyTemplate, nil)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-exclude-id", func(t *testing.T) {
		filter, err := New(&Config{
			ExcludeIds: []string{"cve-test"},
		})
		require.Nil(t, err)
		dummyTemplate := newDummyTemplate("cve-test1", nil, nil, severity.High, types.DNSProtocol)
		matched, _ := filter.Match(dummyTemplate, nil)
		require.True(t, matched, "could not get correct match")
		dummyTemplate = newDummyTemplate("cve-test", []string{"fuzz"}, []string{"pdteam"}, severity.Low, types.HTTPProtocol)
		matched, _ = filter.Match(dummyTemplate, nil)
		require.False(t, matched, "could not get correct match")
	})
	t.Run("match-exclude-type", func(t *testing.T) {
		filter, err := New(&Config{
			ExcludeProtocols: []types.ProtocolType{types.HTTPProtocol},
		})
		require.Nil(t, err)

		dummyTemplate := newDummyTemplate("", []string{"fuzz"}, []string{"pdteam"}, severity.High, types.DNSProtocol)
		matched, _ := filter.Match(dummyTemplate, nil)
		require.True(t, matched, "could not get correct match")
		dummyTemplate = newDummyTemplate("", []string{"fuzz"}, []string{"pdteam"}, severity.Low, types.HTTPProtocol)
		matched, _ = filter.Match(dummyTemplate, nil)
		require.False(t, matched, "could not get correct match")
	})
	advancedFilter, err := New(&Config{
		IncludeConditions: []string{
			"id=='test'",
			"'test' in tags",
		},
	})
	require.Nil(t, err)
	t.Run("advanced-filtering-positive", func(t *testing.T) {
		dummyTemplate := newDummyTemplate("test", []string{"jira", "test"}, []string{"test1", "test2"}, severity.High, types.HTTPProtocol)
		matched, _ := advancedFilter.Match(dummyTemplate, nil)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("advanced-filtering-negative", func(t *testing.T) {
		dummyTemplate := newDummyTemplate("test", []string{"jira"}, []string{"test1", "test2"}, severity.High, types.HTTPProtocol)
		matched, _ := advancedFilter.Match(dummyTemplate, nil)
		require.False(t, matched, "could not get correct match")
	})
}
