package filter

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/stretchr/testify/require"
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

	t.Run("advanced-filtering-positive", func(t *testing.T) {
		dummyTemplate := newDummyTemplate("test", []string{"jira", "test"}, []string{"test1", "test2"}, severity.High, types.HTTPProtocol)

		// syntax error
		testAdvancedFiltering(t, []string{"id==test'"}, dummyTemplate, true, false)
		// basic properties
		testAdvancedFiltering(t, []string{"id=='test'"}, dummyTemplate, false, true)
		// simple element in slice with 'in' operator, multiple slice elements will require a custom helper function
		testAdvancedFiltering(t, []string{"contains(tags,'test')"}, dummyTemplate, false, true)
		testAdvancedFiltering(t, []string{"contains(authors,'test1')"}, dummyTemplate, false, true)
		// helper function
		testAdvancedFiltering(t, []string{"contains(id, 'te')"}, dummyTemplate, false, true)
		testAdvancedFiltering(t, []string{"md5(id)=='098f6bcd4621d373cade4e832627b4f6'"}, dummyTemplate, false, true)
		// boolean operators
		testAdvancedFiltering(t, []string{"id!='nothing' && (contains(id, 'te') && id=='test')&& !contains(tags,'no_tag')"}, dummyTemplate, false, true)
		// create some metadata
		dummyTemplate.Info.Metadata = make(map[string]interface{})
		dummyTemplate.Info.Metadata["test_value"] = "test"
		dummyTemplate.Info.Metadata["bool_value"] = true
		dummyTemplate.Info.Metadata["number_value"] = 1
		testAdvancedFiltering(t, []string{"test_value == 'test' && bool_value && number_value>=1"}, dummyTemplate, false, true)
		// some templates exist with hyphenated fields in the Metadata section.
		dummyTemplate.Info.Metadata["tool-query"] = "test-toolkit"
		testAdvancedFiltering(t, []string{"tool_query == 'test-toolkit'"}, dummyTemplate, false, true)
	})
	t.Run("advanced-filtering-negative", func(t *testing.T) {
		dummyTemplate := newDummyTemplate("test", []string{"jira"}, []string{"test1", "test2"}, severity.High, types.HTTPProtocol)

		// basic properties
		testAdvancedFiltering(t, []string{"id=='test1'"}, dummyTemplate, false, false)
		testAdvancedFiltering(t, []string{"!(id==test') && !contains(tags,'bla')"}, dummyTemplate, true, false)
		// helper function
		testAdvancedFiltering(t, []string{"!contains(id, 'bah')"}, dummyTemplate, false, true)
		// boolean operators with nested negations
		testAdvancedFiltering(t, []string{"id!='nothing' && !(!contains(id, 'te') && id=='test')&& !contains(tags,'no_tag')"}, dummyTemplate, false, true)
		// create some metadata
		dummyTemplate.Info.Metadata = make(map[string]interface{})
		testAdvancedFiltering(t, []string{"non_existent_value == 'test'"}, dummyTemplate, false, false)
	})
	t.Run("template-condition", func(t *testing.T) {
		dummyTemplate := newDummyTemplate("test", []string{"jira"}, []string{"test1", "test2"}, severity.High, types.HTTPProtocol)

		// create some classification
		dummyTemplate.Info.Classification = &model.Classification{
			CVEID:       stringslice.StringSlice{Value: []string{"test-CVEID"}},
			CWEID:       stringslice.StringSlice{Value: []string{"test-CWEID"}},
			CVSSMetrics: "CVSS:3.1/AB:C/DE:F/GH:I/JK:L/M:N/O:P/Q:R/S:T",
			CVSSScore:   5,
			EPSSScore:   0.012345,
			CPE:         "cpe:2.3:a:test:collaboration:1.0.0:-:*:*:*:*:*:*",
		}
		testAdvancedFiltering(t, []string{"cvss_score==5"}, dummyTemplate, false, true)
		testAdvancedFiltering(t, []string{"cvss_score>=4"}, dummyTemplate, false, true)
		testAdvancedFiltering(t, []string{"epss_score==0.012345"}, dummyTemplate, false, true)
		testAdvancedFiltering(t, []string{"cpe=='cpe:2.3:a:test:collaboration:1.0.0:-:*:*:*:*:*:*'"}, dummyTemplate, false, true)
		testAdvancedFiltering(t, []string{"contains(cpe,'cpe:2.3')"}, dummyTemplate, false, true)
		testAdvancedFiltering(t, []string{"cvss_metrics=='CVSS:3.1/AB:C/DE:F/GH:I/JK:L/M:N/O:P/Q:R/S:T'"}, dummyTemplate, false, true)
		testAdvancedFiltering(t, []string{"contains(cvss_metrics,'AB:C')"}, dummyTemplate, false, true)
		testAdvancedFiltering(t, []string{"contains(cwe_id,'test-CWEID')"}, dummyTemplate, false, true)
		testAdvancedFiltering(t, []string{"contains(cve_id,'test-CVEID')"}, dummyTemplate, false, true)
		testAdvancedFiltering(t, []string{"cvss_score>=6"}, dummyTemplate, false, false)
		// cve_id and cwe_id are arrays, the `==` operator does not work on arrays.
		testAdvancedFiltering(t, []string{"cve_id=='test-CVEID'"}, dummyTemplate, false, false)
		testAdvancedFiltering(t, []string{"cwe_id=='test-CWEID'"}, dummyTemplate, false, false)
	})
}

func testAdvancedFiltering(t *testing.T, includeConditions []string, template *templates.Template, shouldError, shouldMatch bool) {
	// basic properties
	advancedFilter, err := New(&Config{IncludeConditions: includeConditions})
	if shouldError {
		require.NotNil(t, err)
		return
	} else {
		require.Nil(t, err)
	}
	matched, _ := advancedFilter.Match(template, nil)
	require.Equal(t, shouldMatch, matched, "could not get correct match")
}
