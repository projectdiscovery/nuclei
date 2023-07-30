package generators

import (
	"os"
	"testing"
	"github.com/stretchr/testify/require"
)

func TestReadVarsFromFile(t *testing.T) {
	content := `var1=value1
var2=value2
var3=value3
var1=value11
var4=value4=
var5
var6 = value6`
	tmp, err := os.CreateTemp("", "vars.*.txt")

	if err != nil {
		t.Fatalf("Create a file failed: %v", err)
	}
	defer tmp.Close()
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(content); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	vars, err := ReadVarsFromFile(tmp.Name())

	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	got := map[string]interface{}{
		"var1": "value11", // Override
		"var2": "value2",
		"var3": "value3",
		"var4": "value4=",
		"var6": "value6",
	}
	require.Equal(t, vars, got, "vars not equal")
}
