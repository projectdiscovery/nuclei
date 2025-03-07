package util

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMarkDownHeaderCreation(t *testing.T) {
	testCases := []struct {
		headers       []string
		expectedValue string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"one"}, "| one |\n| --- |\n"},
		{[]string{"one", "two"}, "| one | two |\n| --- | --- |\n"},
		{[]string{"one", "two", "three"}, "| one | two | three |\n| --- | --- | --- |\n"},
	}

	for _, currentTestCase := range testCases {
		t.Run(strings.Join(currentTestCase.headers, ","), func(t1 *testing.T) {
			require.Equal(t1, CreateTableHeader(currentTestCase.headers...), currentTestCase.expectedValue)
		})
	}
}

func TestCreateTemplateInfoTableTooManyColumns(t *testing.T) {
	table, err := CreateTable([]string{"one", "two"}, [][]string{
		{"a", "b", "c"},
		{"d"},
		{"e", "f", "g"},
		{"h", "i"},
	})

	require.NotNil(t, err)
	require.Empty(t, table)
}

func TestCreateTemplateInfoTable1Column(t *testing.T) {
	table, err := CreateTable([]string{"one"}, [][]string{{"a"}, {"b"}, {"c"}})

	expected := `| one |
| --- |
| a |
| b |
| c |
`

	require.Nil(t, err)
	require.Equal(t, expected, table)
}

func TestCreateTemplateInfoTable2Columns(t *testing.T) {
	table, err := CreateTable([]string{"one", "two"}, [][]string{
		{"a", "b"},
		{"c"},
		{"d", "e"},
	})

	expected := `| one | two |
| --- | --- |
| a | b |
| c |  |
| d | e |
`

	require.Nil(t, err)
	require.Equal(t, expected, table)
}

func TestCreateTemplateInfoTable3Columns(t *testing.T) {
	table, err := CreateTable([]string{"one", "two", "three"}, [][]string{
		{"a", "b", "c"},
		{"d"},
		{"e", "f", "g"},
		{"h", "i"},
	})

	expected := `| one | two | three |
| --- | --- | --- |
| a | b | c |
| d |  |  |
| e | f | g |
| h | i |  |
`

	require.Nil(t, err)
	require.Equal(t, expected, table)
}

func TestEscapeCodeBlockMarkdown(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no special characters",
			input:    "normal text without special chars",
			expected: "normal text without special chars",
		},
		{
			name:     "with backticks",
			input:    "text with `backticks` inside",
			expected: "text with \\`backticks\\` inside",
		},
		{
			name:     "with backslashes",
			input:    "text with \\ backslash",
			expected: "text with \\\\ backslash",
		},
		{
			name:     "with both backticks and backslashes",
			input:    "text with `backticks` and \\ backslash",
			expected: "text with \\`backticks\\` and \\\\ backslash",
		},
		{
			name:     "with code block",
			input:    "```code block```",
			expected: "\\`\\`\\`code block\\`\\`\\`",
		},
		{
			name:     "with escaped backtick",
			input:    "escaped \\` backtick",
			expected: "escaped \\\\\\` backtick",
		},
		{
			name:     "with multiple consecutive backticks",
			input:    "``double backticks``",
			expected: "\\`\\`double backticks\\`\\`",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := escapeCodeBlockMarkdown(tc.input)
			require.Equal(t, tc.expected, result, "Failed to properly escape markdown for code blocks")
		})
	}
}
