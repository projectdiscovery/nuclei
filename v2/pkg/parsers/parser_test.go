package parsers

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
)

func TestLoadTemplate(t *testing.T) {
	origTemplatesCache := parsedTemplatesCache
	defer func() { parsedTemplatesCache = origTemplatesCache }()

	tt := []struct {
		name        string
		template    *templates.Template
		templateErr error

		expectedErr error
	}{
		{
			name: "valid",
			template: &templates.Template{
				ID: "CVE-2021-27330",
				Info: model.Info{
					Name:    "Valid template",
					Authors: stringslice.StringSlice{Value: "Author"},
				},
			},
		},
		{
			name:        "emptyTemplate",
			template:    &templates.Template{},
			expectedErr: errors.New("mandatory 'name' field is missing, mandatory 'author' field is missing, mandatory 'id' field is missing"),
		},
		{
			name: "emptyNameWithInvalidID",
			template: &templates.Template{
				ID: "invalid id",
				Info: model.Info{
					Authors: stringslice.StringSlice{Value: "Author"},
				},
			},
			expectedErr: errors.New("mandatory 'name' field is missing, invalid field format for 'id' (allowed format is ^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$)"),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			parsedTemplatesCache.Store(tc.name, tc.template, tc.templateErr)

			tagFilter := filter.New(&filter.Config{})
			success, err := LoadTemplate(tc.name, tagFilter, nil)
			if tc.expectedErr == nil {
				require.NoError(t, err)
				require.True(t, success)
			} else {
				require.Equal(t, tc.expectedErr, err)
				require.False(t, success)
			}
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
						Name:    "Valid template",
						Authors: stringslice.StringSlice{Value: "Author"},
					},
				}
				parsedTemplatesCache.Store(name, template, nil)

				tagFilter := filter.New(&filter.Config{})
				success, err := LoadTemplate(name, tagFilter, nil)
				if tc.success {
					require.NoError(t, err)
					require.True(t, success)
				} else {
					require.Equal(t, errors.New("invalid field format for 'id' (allowed format is ^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$)"), err)
					require.False(t, success)
				}
			})
		}
	})
}
