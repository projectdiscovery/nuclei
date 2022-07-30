package filter

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

// original
// Match(templateTags, templateAuthors []string, templateSeverity severity.Severity, extraTags []string, templateType types.ProtocolType, templateId string)

func TestTagBasedFilter(t *testing.T) {
	{
		filter, err := New(&Config{
			Tags: []string{"cves", "2021", "jira"},
		})
		require.Nil(t, err)

		t.Run("true", func(t *testing.T) {
			dummyTemplate := &templates.Template{
				Info: model.Info{
					Tags:           stringslice.StringSlice{Value: []string{"jira"}},
					Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
					SeverityHolder: severity.Holder{Severity: severity.Low},
				},
				RequestsHTTP: []*http.Request{{}, {}},
			}
			matched, _ := filter.Match(dummyTemplate, nil)
			require.True(t, matched, "could not get correct match")
		})
		t.Run("false", func(t *testing.T) {
			dummyTemplate := &templates.Template{
				Info: model.Info{
					Tags:           stringslice.StringSlice{Value: []string{"consul"}},
					Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
					SeverityHolder: severity.Holder{Severity: severity.Low},
				},
				RequestsHTTP: []*http.Request{{}, {}},
			}
			matched, _ := filter.Match(dummyTemplate, nil)
			require.False(t, matched, "could not get correct match")
		})
		t.Run("match-extra-tags-positive", func(t *testing.T) {
			dummyTemplate := &templates.Template{
				Info: model.Info{
					Tags:           stringslice.StringSlice{Value: []string{"cves", "vuln"}},
					Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
					SeverityHolder: severity.Holder{Severity: severity.Low},
				},
				RequestsHTTP: []*http.Request{{}, {}},
			}
			matched, _ := filter.Match(dummyTemplate, []string{"vuln"})
			require.True(t, matched, "could not get correct match")
		})
		t.Run("match-extra-tags-negative", func(t *testing.T) {
			dummyTemplate := &templates.Template{
				Info: model.Info{
					Tags:           stringslice.StringSlice{Value: []string{"cves"}},
					Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
					SeverityHolder: severity.Holder{Severity: severity.Low},
				},
				RequestsHTTP: []*http.Request{{}, {}},
			}
			matched, _ := filter.Match(dummyTemplate, []string{"vuln"})
			require.False(t, matched, "could not get correct match")
		})
	}

	t.Run("not-match-excludes", func(t *testing.T) {
		filter, err := New(&Config{
			ExcludeTags: []string{"dos"},
		})
		require.Nil(t, err)
		dummyTemplate := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"dos"}},
				Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
				SeverityHolder: severity.Holder{Severity: severity.Low},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
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
		dummyTemplate := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"fuzz"}},
				Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
				SeverityHolder: severity.Holder{Severity: severity.Low},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
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
		dummyTemplate := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"fuzz"}},
				Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
				SeverityHolder: severity.Holder{Severity: severity.Low},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
		matched, err := filter.Match(dummyTemplate, nil)
		require.Nil(t, err, "could not get match")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-author", func(t *testing.T) {
		filter, err := New(&Config{
			Authors: []string{"pdteam"},
		})
		require.Nil(t, err)
		dummyTemplate := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"fuzz"}},
				Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
				SeverityHolder: severity.Holder{Severity: severity.Low},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
		matched, _ := filter.Match(dummyTemplate, nil)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-severity", func(t *testing.T) {
		filter, err := New(&Config{
			Severities: severity.Severities{severity.High},
		})
		require.Nil(t, err)
		dummyTemplate := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"fuzz"}},
				Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
				SeverityHolder: severity.Holder{Severity: severity.High},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
		matched, _ := filter.Match(dummyTemplate, nil)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-id", func(t *testing.T) {
		filter, err := New(&Config{
			IncludeIds: []string{"cve-test"},
		})
		require.Nil(t, err)
		dummyTemplate := &templates.Template{
			ID: "cve-test",
			Info: model.Info{
				SeverityHolder: severity.Holder{Severity: severity.Low},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
		matched, _ := filter.Match(dummyTemplate, nil)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-exclude-severity", func(t *testing.T) {
		filter, err := New(&Config{
			ExcludeSeverities: severity.Severities{severity.Low},
		})
		require.Nil(t, err)
		dummyTemplate1 := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"fuzz"}},
				Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
				SeverityHolder: severity.Holder{Severity: severity.High},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
		matched, _ := filter.Match(dummyTemplate1, nil)
		require.True(t, matched, "could not get correct match")

		dummyTemplate2 := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"fuzz"}},
				Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
				SeverityHolder: severity.Holder{Severity: severity.Low},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
		matched, _ = filter.Match(dummyTemplate2, nil)
		require.False(t, matched, "could not get correct match")
	})
	t.Run("match-exclude-with-tags", func(t *testing.T) {
		filter, err := New(&Config{
			Tags:        []string{"tag"},
			ExcludeTags: []string{"another"},
		})
		require.Nil(t, err)
		dummyTemplate := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"another"}},
				Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
				SeverityHolder: severity.Holder{Severity: severity.High},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
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

		dummyTemplate1 := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"jira", "cve"}},
				Authors:        stringslice.StringSlice{Value: []string{"pdteam", "someOtherUser"}},
				SeverityHolder: severity.Holder{Severity: severity.High},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
		matched, _ := filter.Match(dummyTemplate1, nil)
		require.True(t, matched, "could not get correct match")

		dummyTemplate2 := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"jira"}},
				Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
				SeverityHolder: severity.Holder{Severity: severity.Low},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
		matched, _ = filter.Match(dummyTemplate2, nil)
		require.False(t, matched, "could not get correct match")

		dummyTemplate3 := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"jira"}},
				Authors:        stringslice.StringSlice{Value: []string{"random"}},
				SeverityHolder: severity.Holder{Severity: severity.Low},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
		matched, _ = filter.Match(dummyTemplate3, nil)
		require.False(t, matched, "could not get correct match")

		dummyTemplate4 := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"consul"}},
				Authors:        stringslice.StringSlice{Value: []string{"random"}},
				SeverityHolder: severity.Holder{Severity: severity.Low},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
		matched, _ = filter.Match(dummyTemplate4, nil)
		require.False(t, matched, "could not get correct match")
	})
	t.Run("match-type", func(t *testing.T) {
		filter, err := New(&Config{
			Protocols: []types.ProtocolType{types.HTTPProtocol},
		})
		require.Nil(t, err)

		dummyTemplate := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"fuzz"}},
				Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
				SeverityHolder: severity.Holder{Severity: severity.High},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
		matched, _ := filter.Match(dummyTemplate, nil)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-exclude-id", func(t *testing.T) {
		filter, err := New(&Config{
			ExcludeIds: []string{"cve-test"},
		})
		require.Nil(t, err)
		dummyTemplate1 := &templates.Template{
			ID: "cve-test1",
			Info: model.Info{
				SeverityHolder: severity.Holder{Severity: severity.High},
			},
			RequestsDNS: []*dns.Request{{}, {}},
		}
		matched, _ := filter.Match(dummyTemplate1, nil)
		require.True(t, matched, "could not get correct match")

		dummyTemplate2 := &templates.Template{
			ID: "cve-test",
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"fuzz"}},
				Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
				SeverityHolder: severity.Holder{Severity: severity.Low},
			},
			RequestsHTTP: []*http.Request{{}, {}},
		}
		matched, _ = filter.Match(dummyTemplate2, nil)
		require.False(t, matched, "could not get correct match")
	})
	t.Run("match-exclude-type", func(t *testing.T) {
		filter, err := New(&Config{
			ExcludeProtocols: []types.ProtocolType{types.HTTPProtocol},
		})
		require.Nil(t, err)

		dummyTemplate1 := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"fuzz"}},
				Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
				SeverityHolder: severity.Holder{Severity: severity.High},
			},
			RequestsDNS: []*dns.Request{{}, {}},
		}
		matched, _ := filter.Match(dummyTemplate1, nil)
		require.True(t, matched, "could not get correct match")

		dummyTemplate2 := &templates.Template{
			Info: model.Info{
				Tags:           stringslice.StringSlice{Value: []string{"fuzz"}},
				Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
				SeverityHolder: severity.Holder{Severity: severity.Low},
			},
			RequestsHTTP: []*http.Request{{}},
		}
		matched, _ = filter.Match(dummyTemplate2, nil)
		require.False(t, matched, "could not get correct match")
	})
}
