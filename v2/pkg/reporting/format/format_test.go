package format

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/projectdiscovery/nuclei/v2/internal/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
)

func TestToMarkdownTableString(t *testing.T) {
	info := model.Info{
		Name:           "Test Template Name",
		Authors:        model.StringSlice{Value: []string{"forgedhallpass", "ice3man"}},
		Description:    "Test description",
		SeverityHolder: severity.SeverityHolder{Severity: severity.High},
		Tags:           model.StringSlice{Value: []string{"cve", "misc"}},
		Reference:      model.StringSlice{Value: "reference1"},
		CustomAttributes: map[string]string{
			"customDynamicKey1": "customDynamicValue1",
			"customDynamicKey2": "customDynamicValue2",
		},
	}

	result := ToMarkdownTableString(&info)

	expectedOrderedAttributes := `| Name | Test Template Name |
| Authors | forgedhallpass, ice3man |
| Tags | cve, misc |
| Severity | high |
| Description | Test description |`

	expectedDynamicAttributes := []string{
		"| customDynamicKey1 | customDynamicValue1 |",
		"| customDynamicKey2 | customDynamicValue2 |",
		"", // the expected result ends in a new line (\n)
	}

	actualAttributeSlice := strings.Split(result, "\n")
	dynamicAttributeIndex := len(actualAttributeSlice) - len(expectedDynamicAttributes)
	assert.Equal(t, strings.Split(expectedOrderedAttributes, "\n"), actualAttributeSlice[:dynamicAttributeIndex]) // the first part of the result is ordered
	assert.ElementsMatch(t, expectedDynamicAttributes, actualAttributeSlice[dynamicAttributeIndex:])              // dynamic parameters are not ordered
}
