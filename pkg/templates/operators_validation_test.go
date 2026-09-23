package templates_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/stretchr/testify/require"
)

func TestParseTemplateRejectsOperatorsWithoutValues(t *testing.T) {
	for _, validationMode := range []bool{false, true} {
		t.Run(fmt.Sprintf("validation=%t", validationMode), func(t *testing.T) {
			options := testutils.DefaultOptions.Copy()
			options.Validate = validationMode
			options.ExecutionId = t.Name()
			testutils.Init(options)
			t.Cleanup(func() { testutils.Cleanup(options) })

			for _, tt := range []struct {
				kind string
				typ  string
			}{
				{"matcher", "word"},
				{"extractor", "regex"},
			} {
				t.Run(tt.kind, func(t *testing.T) {
					executerOptions := testutils.NewMockExecuterOptions(options, nil)
					templateSource := fmt.Sprintf(`id: empty-operator
info:
  name: Empty operator
  author: pdteam
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    %ss:
      - type: %s
`, tt.kind, tt.typ)
					template, err := templates.ParseTemplateFromReader(strings.NewReader(templateSource), nil, executerOptions)
					require.ErrorContains(t, err, "could not compile "+tt.kind)
					require.ErrorContains(t, err, tt.typ+" "+tt.kind+" requires at least one")
					require.Nil(t, template)
				})
			}
		})
	}
}
