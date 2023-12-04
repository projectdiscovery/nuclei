package jira

import (
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

func TestLinkCreation(t *testing.T) {
	jiraIntegration := &Integration{}
	link := jiraIntegration.CreateLink("ProjectDiscovery", "https://projectdiscovery.io")
	assert.Equal(t, "[ProjectDiscovery|https://projectdiscovery.io]", link)
}

func TestHorizontalLineCreation(t *testing.T) {
	jiraIntegration := &Integration{}
	horizontalLine := jiraIntegration.CreateHorizontalLine()
	assert.True(t, strings.Contains(horizontalLine, "----"))
}

func TestTableCreation(t *testing.T) {
	jiraIntegration := &Integration{}

	table, err := jiraIntegration.CreateTable([]string{"key", "value"}, [][]string{
		{"a", "b"},
		{"c"},
		{"d", "e"},
	})

	assert.Nil(t, err)
	expected := `| key | value |
| a | b |
| c |  |
| d | e |
`
	assert.Equal(t, expected, table)
}

func TestStatusNotCustomUnmarshal(t *testing.T) {
	type Data struct {
		StatusNot StringArrayCoerced `yaml:"status-not" json:"status_not"`
	}

	scenarios := [][]byte{
		[]byte("status-not: Testing"),
		[]byte(`status-not:
        - Testing`),
		[]byte(`status-not:
        - Testing
        - Testing`),
	}

	for _, scenario := range scenarios {
		data := Data{}
		assert.Nil(t, yaml.Unmarshal(scenario, &data))
		assert.Equal(t, "Testing", data.StatusNot[0])
	}
}
