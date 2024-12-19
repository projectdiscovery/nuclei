package vardump

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDumpVariables(t *testing.T) {
	// Enable var dump for testing
	EnableVarDump = true

	// Test case
	testVars := variables{
		"string": "test",
		"int":    42,
		"bool":   true,
		"slice":  []string{"a", "b", "c"},
	}

	result := DumpVariables(testVars)

	// Assertions
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "string")
	assert.Contains(t, result, "test")
	assert.Contains(t, result, "int")
	assert.Contains(t, result, "42")
	assert.Contains(t, result, "bool")
	assert.Contains(t, result, "true")
	assert.Contains(t, result, "slice")
	assert.Contains(t, result, "a")
	assert.Contains(t, result, "b")
	assert.Contains(t, result, "c")

}

func TestProcess(t *testing.T) {
	testVars := variables{
		"short":  "short string",
		"long":   strings.Repeat("a", 300),
		"number": 42,
	}

	processed := process(testVars, 255)

	assert.Equal(t, "short string", processed["short"])
	assert.Equal(t, strings.Repeat("a", 255)+" [...]", processed["long"])
	assert.Equal(t, "42", processed["number"])
}
