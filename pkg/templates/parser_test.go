package templates

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/stretchr/testify/require"
)

func TestLoadTemplate(t *testing.T) {
	catalog := disk.NewCatalog("")
	p := NewParser()

	tt := []struct {
		name        string
		template    *Template
		templateErr error
		filter      TagFilterConfig

		expectedErr error
		isValid     bool
	}{
		{
			name: "valid",
			template: &Template{
				ID: "CVE-2021-27330",
				Info: model.Info{
					Name:           "Valid template",
					Authors:        stringslice.StringSlice{Value: "Author"},
					SeverityHolder: severity.Holder{Severity: severity.Medium},
				},
			},
			isValid: true,
		},
		{
			name:        "emptyTemplate",
			template:    &Template{},
			isValid:     false,
			expectedErr: errors.New("cause=\"Could not load template emptyTemplate: cause=\\\"mandatory 'name' field is missing\\\"\\ncause=\\\"mandatory 'author' field is missing\\\"\\ncause=\\\"mandatory 'id' field is missing\\\"\""),
		},
		{
			name: "emptyNameWithInvalidID",
			template: &Template{
				ID: "invalid id",
				Info: model.Info{
					Authors:        stringslice.StringSlice{Value: "Author"},
					SeverityHolder: severity.Holder{Severity: severity.Medium},
				},
			},
			expectedErr: errors.New("cause=\"Could not load template emptyNameWithInvalidID: cause=\\\"mandatory 'name' field is missing\\\"\\ncause=\\\"invalid field format for 'id' (allowed format is ^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$)\\\"\""),
		},
		{
			name: "emptySeverity",
			template: &Template{
				ID: "CVE-2021-27330",
				Info: model.Info{
					Name:    "Valid template",
					Authors: stringslice.StringSlice{Value: "Author"},
				},
			},
			isValid:     true,
			expectedErr: errors.New("field 'severity' is missing"),
		},
		{
			name: "template-without-severity-with-correct-filter-id",
			template: &Template{
				ID: "CVE-2021-27330",
				Info: model.Info{
					Name:    "Valid template",
					Authors: stringslice.StringSlice{Value: "Author"},
				},
			},
			// should be error because the template is loaded
			expectedErr: errors.New("field 'severity' is missing"),
			isValid:     true,
			filter:      TagFilterConfig{IncludeIds: []string{"CVE-2021-27330"}},
		},
		{
			name: "template-without-severity-with-diff-filter-id",
			template: &Template{
				ID: "CVE-2021-27330",
				Info: model.Info{
					Name:    "Valid template",
					Authors: stringslice.StringSlice{Value: "Author"},
				},
			},
			isValid: false,
			filter:  TagFilterConfig{IncludeIds: []string{"another-id"}},
			// no error because the template is not loaded
			expectedErr: nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			p.parsedTemplatesCache.Store(tc.name, tc.template, nil, tc.templateErr)

			tagFilter, err := NewTagFilter(&tc.filter)
			require.Nil(t, err)
			success, err := p.LoadTemplate(tc.name, tagFilter, nil, catalog)
			if tc.expectedErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.expectedErr.Error())
			}
			require.Equal(t, tc.isValid, success)
		})
	}

	// Regression test for projectdiscovery/nuclei#7448.
	//
	// Templates loaded from JSON used to silently accept unknown fields because
	// [Template.UnmarshalJSON] delegated to a non-strict json.Unmarshal call.
	// That meant `-validate` would pass templates that contained typoed fields
	// or HTTP-only fields on a network.Request block, which then failed at
	// runtime with the unknown-field error. Strict mode is the default and
	// must be opt-out via [NoStrictJSON] (set from the runner's
	// `-no-strict-syntax` flag).
	t.Run("strictJSONRejectsUnknownFields", func(t *testing.T) {
		const tmpl = `{
  "id": "JSON-UNKNOWN-FIELD",
  "info": {
    "name": "strict json regression",
    "author": "anonymous",
    "severity": "info",
    "tags": "test"
  },
  "tcp": [{
    "host": ["{{Hostname}}"],
    "port": "80",
    "name": "first_read",
    "req-condition": true,
    "bogus_field_42": "anything",
    "inputs": [{"data": "X"}],
    "matchers": [{"type": "word", "words": ["HTTP"]}]
  }]
}`
		dir := t.TempDir()
		path := filepath.Join(dir, "tmpl.json")
		require.NoError(t, os.WriteFile(path, []byte(tmpl), 0o600))

		// Strict mode (default): unknown fields must be rejected.
		prev := NoStrictJSON
		t.Cleanup(func() { NoStrictJSON = prev })

		NoStrictJSON = false
		strictParser := NewParser()
		_, err := strictParser.ParseTemplate(path, disk.NewCatalog(""))
		require.Error(t, err, "expected strict JSON decode to reject unknown fields")
		require.Contains(t, err.Error(), "unknown field", "expected unknown-field error, got: %v", err)

		// Lax mode: when NoStrictJSON is set (via the -no-strict-syntax flag)
		// the same template must still parse, preserving the historical opt-out.
		NoStrictJSON = true
		laxParser := NewParser()
		laxParser.NoStrictSyntax = true
		laxPath := filepath.Join(dir, "tmpl-lax.json")
		require.NoError(t, os.WriteFile(laxPath, []byte(tmpl), 0o600))
		_, err = laxParser.ParseTemplate(laxPath, disk.NewCatalog(""))
		require.NoError(t, err, "NoStrictJSON should allow unknown fields")
	})

	t.Run("invalidTemplateID", func(t *testing.T) {
		tt := []struct {
			id      string
			success bool
		}{
			{id: "A-B-C", success: true},
			{id: "A-B-C-1", success: true},
			{id: "CVE_2021_27330", success: true},
			{id: "ABC DEF", success: false},
			{id: "_-__AAA_", success: false},
			{id: " CVE-2021-27330", success: false},
			{id: "CVE-2021-27330 ", success: false},
			{id: "CVE-2021-27330-", success: false},
			{id: "-CVE-2021-27330-", success: false},
			{id: "CVE-2021--27330", success: false},
			{id: "CVE-2021+27330", success: false},
		}
		for i, tc := range tt {
			name := fmt.Sprintf("regexp%d", i)
			t.Run(name, func(t *testing.T) {
				template := &Template{
					ID: tc.id,
					Info: model.Info{
						Name:           "Valid template",
						Authors:        stringslice.StringSlice{Value: "Author"},
						SeverityHolder: severity.Holder{Severity: severity.Medium},
					},
				}
				p.parsedTemplatesCache.Store(name, template, nil, nil)

				tagFilter, err := NewTagFilter(&TagFilterConfig{})
				require.Nil(t, err)
				success, err := p.LoadTemplate(name, tagFilter, nil, catalog)
				if tc.success {
					require.NoError(t, err)
					require.True(t, success)
				} else {
					require.ErrorContains(t, err, "invalid field format for 'id' (allowed format is ^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$)")
					require.False(t, success)
				}
			})
		}
	})
}
