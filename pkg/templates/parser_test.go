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
	// must be opt-out via the parser's [Parser.NoStrictSyntax] field (set
	// from the runner's `-no-strict-syntax` flag).
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
		strictPath := filepath.Join(dir, "tmpl-strict.json")
		require.NoError(t, os.WriteFile(strictPath, []byte(tmpl), 0o600))

		// Strict mode (default): unknown fields must be rejected.
		strictParser := NewParser()
		_, err := strictParser.ParseTemplate(strictPath, disk.NewCatalog(""))
		require.Error(t, err, "expected strict JSON decode to reject unknown fields")
		require.Contains(t, err.Error(), "unknown field", "expected unknown-field error, got: %v", err)

		// Lax mode: when the parser opts out via NoStrictSyntax (set from the
		// `-no-strict-syntax` flag) the same template must still parse.
		laxParser := NewParser()
		laxParser.NoStrictSyntax = true
		laxPath := filepath.Join(dir, "tmpl-lax.json")
		require.NoError(t, os.WriteFile(laxPath, []byte(tmpl), 0o600))
		_, err = laxParser.ParseTemplate(laxPath, disk.NewCatalog(""))
		require.NoError(t, err, "NoStrictSyntax should allow unknown fields")
	})

	// json.Decoder by design only consumes one top-level value. Without an
	// explicit EOF check, concatenated JSON documents would silently load
	// only the first — e.g. `{"id":"safe"...}{"id":"hijack"...}` would scan
	// under the safe id while the second document is ignored.
	t.Run("strictJSONRejectsTrailingData", func(t *testing.T) {
		const tmpl = `{
  "id": "JSON-TRAILING-DATA",
  "info": {
    "name": "trailing data regression",
    "author": "anonymous",
    "severity": "info"
  },
  "http": [{
    "method": "GET",
    "path": ["{{BaseURL}}"],
    "matchers": [{"type": "word", "words": ["HTTP"]}]
  }]
}
{"id":"HIJACK","info":{"name":"x","author":"y","severity":"high"}}
`
		dir := t.TempDir()
		path := filepath.Join(dir, "tmpl.json")
		require.NoError(t, os.WriteFile(path, []byte(tmpl), 0o600))

		_, err := NewParser().ParseTemplate(path, disk.NewCatalog(""))
		require.Error(t, err, "expected strict JSON to reject trailing data")
		require.Contains(t, err.Error(), "trailing data", "expected trailing-data error, got: %v", err)
	})

	// Strictness is a per-parser setting (not a process global) so two
	// parsers in the same process with different `-no-strict-syntax` values
	// must not interfere with each other. Cf. concurrent-engines support
	// introduced in #6322.
	t.Run("strictJSONIsPerParser", func(t *testing.T) {
		const tmpl = `{
  "id": "JSON-PER-PARSER",
  "info": {
    "name": "per-parser strictness",
    "author": "anonymous",
    "severity": "info"
  },
  "http": [{
    "method": "GET",
    "path": ["{{BaseURL}}"],
    "matchers": [{"type": "word", "words": ["HTTP"]}],
    "bogus_field": "ignore me"
  }]
}`
		dir := t.TempDir()
		strictPath := filepath.Join(dir, "per-parser-strict.json")
		laxPath := filepath.Join(dir, "per-parser-lax.json")
		require.NoError(t, os.WriteFile(strictPath, []byte(tmpl), 0o600))
		require.NoError(t, os.WriteFile(laxPath, []byte(tmpl), 0o600))

		strictParser := NewParser()
		laxParser := NewParser()
		laxParser.NoStrictSyntax = true

		_, strictErr := strictParser.ParseTemplate(strictPath, disk.NewCatalog(""))
		_, laxErr := laxParser.ParseTemplate(laxPath, disk.NewCatalog(""))

		require.Error(t, strictErr, "strict parser must reject unknown field")
		require.Contains(t, strictErr.Error(), "unknown field")
		require.NoError(t, laxErr, "lax parser must accept the same template")
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
