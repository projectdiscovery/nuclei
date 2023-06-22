package util

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
			assert.Equal(t1, CreateTableHeader(currentTestCase.headers...), currentTestCase.expectedValue)
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

	assert.NotNil(t, err)
	assert.Empty(t, table)
}

func TestCreateTemplateInfoTable1Column(t *testing.T) {
	table, err := CreateTable([]string{"one"}, [][]string{{"a"}, {"b"}, {"c"}})

	expected := `| one |
| --- |
| a |
| b |
| c |
`

	assert.Nil(t, err)
	assert.Equal(t, expected, table)
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

	assert.Nil(t, err)
	assert.Equal(t, expected, table)
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

	assert.Nil(t, err)
	assert.Equal(t, expected, table)
}
