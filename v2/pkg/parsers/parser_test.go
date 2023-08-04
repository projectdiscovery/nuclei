package parsers

import (
	"errors"
	"fmt"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/stretchr/testify/require"
)

func TestLoadTemplate(t *testing.T) {
	catalog := disk.NewCatalog("")
	origTemplatesCache := parsedTemplatesCache
	defer func() { parsedTemplatesCache = origTemplatesCache }()

	tt := []struct {
		name        string
		template    *templates.Template
		templateErr error
		filter      filter.Config

		expectedErr error
		isValid     bool
	}{
		{
			name: "valid",
			template: &templates.Template{
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
			template:    &templates.Template{},
			isValid:     false,
			expectedErr: errors.New("mandatory 'name' field is missing, mandatory 'author' field is missing, mandatory 'id' field is missing"),
		},
		{
			name: "emptyNameWithInvalidID",
			template: &templates.Template{
				ID: "invalid id",
				Info: model.Info{
					Authors:        stringslice.StringSlice{Value: "Author"},
					SeverityHolder: severity.Holder{Severity: severity.Medium},
				},
			},
			expectedErr: errors.New("mandatory 'name' field is missing, invalid field format for 'id' (allowed format is ^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$)"),
		},
		{
			name: "emptySeverity",
			template: &templates.Template{
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
			template: &templates.Template{
				ID: "CVE-2021-27330",
				Info: model.Info{
					Name:    "Valid template",
					Authors: stringslice.StringSlice{Value: "Author"},
				},
			},
			// should be error because the template is loaded
			expectedErr: errors.New("field 'severity' is missing"),
			isValid:     true,
			filter:      filter.Config{IncludeIds: []string{"CVE-2021-27330"}},
		},
		{
			name: "template-without-severity-with-diff-filter-id",
			template: &templates.Template{
				ID: "CVE-2021-27330",
				Info: model.Info{
					Name:    "Valid template",
					Authors: stringslice.StringSlice{Value: "Author"},
				},
			},
			isValid: false,
			filter:  filter.Config{IncludeIds: []string{"another-id"}},
			// no error because the template is not loaded
			expectedErr: nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			parsedTemplatesCache.Store(tc.name, tc.template, tc.templateErr)

			tagFilter, err := filter.New(&tc.filter)
			require.Nil(t, err)
			success, err := LoadTemplate(tc.name, tagFilter, nil, catalog)
			if tc.expectedErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.expectedErr.Error())
			}
			require.Equal(t, tc.isValid, success)
		})
	}

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
				template := &templates.Template{
					ID: tc.id,
					Info: model.Info{
						Name:           "Valid template",
						Authors:        stringslice.StringSlice{Value: "Author"},
						SeverityHolder: severity.Holder{Severity: severity.Medium},
					},
				}
				parsedTemplatesCache.Store(name, template, nil)

				tagFilter, err := filter.New(&filter.Config{})
				require.Nil(t, err)
				success, err := LoadTemplate(name, tagFilter, nil, catalog)
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
