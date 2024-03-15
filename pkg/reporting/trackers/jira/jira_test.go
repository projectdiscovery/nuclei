package jira

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLinkCreation(t *testing.T) {
	jiraIntegration := &Integration{}
	link := jiraIntegration.CreateLink("ProjectDiscovery", "https://projectdiscovery.io")
	require.Equal(t, "[ProjectDiscovery|https://projectdiscovery.io]", link)
}

func TestHorizontalLineCreation(t *testing.T) {
	jiraIntegration := &Integration{}
	horizontalLine := jiraIntegration.CreateHorizontalLine()
	require.True(t, strings.Contains(horizontalLine, "----"))
}

func TestTableCreation(t *testing.T) {
	jiraIntegration := &Integration{}

	table, err := jiraIntegration.CreateTable([]string{"key", "value"}, [][]string{
		{"a", "b"},
		{"c"},
		{"d", "e"},
	})

	require.Nil(t, err)
	expected := `| key | value |
| a | b |
| c |  |
| d | e |
`
	require.Equal(t, expected, table)
}
