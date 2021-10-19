package parsers

import (
	"errors"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/stretchr/testify/require"
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
			name:        "missingName",
			template:    &templates.Template{},
			expectedErr: errors.New("mandatory 'name' field is missing"),
		},
		{
			name: "invalidID",
			template: &templates.Template{
				ID: "ABC DEF",
				Info: model.Info{
					Name:    "Invalid ID",
					Authors: stringslice.StringSlice{Value: "Author"},
				},
			},
			expectedErr: errors.New("invalid field format for 'id' (allowed format is ^[A-Za-z0-9-_]+$)"),
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
}
