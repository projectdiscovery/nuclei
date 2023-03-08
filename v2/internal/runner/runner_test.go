package runner

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

func Test_createReportingOptions(t *testing.T) {
	var options types.Options
	options.ReportingConfig = "../../../integration_tests/test-issue-tracker-config1.yaml"
	resultOptions, err := createReportingOptions(&options)

	assert.Nil(t, err)
	assert.Equal(t, resultOptions.AllowList.Severities, severity.Severities{severity.High, severity.Critical})
	assert.Equal(t, resultOptions.DenyList.Severities, severity.Severities{severity.Low})

	options.ReportingConfig = "../../../integration_tests/test-issue-tracker-config2.yaml"
	resultOptions2, err := createReportingOptions(&options)
	assert.Nil(t, err)
	assert.Equal(t, resultOptions2.AllowList.Severities, resultOptions.AllowList.Severities)
	assert.Equal(t, resultOptions2.DenyList.Severities, resultOptions.DenyList.Severities)
}

type TestStruct1 struct {
	A      string       `yaml:"a"`
	Struct *TestStruct2 `yaml:"b"`
}

type TestStruct2 struct {
	B string `yaml:"b"`
}

type TestStruct3 struct {
	A string `yaml:"a"`
	B string `yaml:"b"`
	C string `yaml:"c"`
}

type TestStruct4 struct {
	A      string       `yaml:"a"`
	Struct *TestStruct3 `yaml:"b"`
}

type TestStruct5 struct {
	A []string  `yaml:"a"`
	B [2]string `yaml:"b"`
}

type TestStruct6 struct {
	A string       `yaml:"a"`
	B *TestStruct2 `yaml:"b"`
	C string
}

func TestWalkReflectStructAssignsEnvVars(t *testing.T) {
	testStruct := &TestStruct1{
		A: "$VAR_EXAMPLE",
		Struct: &TestStruct2{
			B: "$VAR_TWO",
		},
	}
	os.Setenv("VAR_EXAMPLE", "value")
	os.Setenv("VAR_TWO", "value2")

	Walk(testStruct, expandEndVars)

	assert.Equal(t, "value", testStruct.A)
	assert.Equal(t, "value2", testStruct.Struct.B)
}

func TestWalkReflectStructHandlesDifferentTypes(t *testing.T) {
	testStruct := &TestStruct3{
		A: "$VAR_EXAMPLE",
		B: "$VAR_TWO",
		C: "$VAR_THREE",
	}
	os.Setenv("VAR_EXAMPLE", "value")
	os.Setenv("VAR_TWO", "2")
	os.Setenv("VAR_THREE", "true")

	Walk(testStruct, expandEndVars)

	assert.Equal(t, "value", testStruct.A)
	assert.Equal(t, "2", testStruct.B)
	assert.Equal(t, "true", testStruct.C)
}

func TestWalkReflectStructEmpty(t *testing.T) {
	testStruct := &TestStruct3{
		A: "$VAR_EXAMPLE",
		B: "",
		C: "$VAR_THREE",
	}
	os.Setenv("VAR_EXAMPLE", "value")
	os.Setenv("VAR_TWO", "2")
	os.Setenv("VAR_THREE", "true")

	Walk(testStruct, expandEndVars)

	assert.Equal(t, "value", testStruct.A)
	assert.Equal(t, "", testStruct.B)
	assert.Equal(t, "true", testStruct.C)
}

func TestWalkReflectStructWithNoYamlTag(t *testing.T) {
	test := &TestStruct6{
		A: "$GITHUB_USER",
		B: &TestStruct2{
			B: "$GITHUB_USER",
		},
		C: "$GITHUB_USER",
	}

	os.Setenv("GITHUB_USER", "testuser")

	Walk(test, expandEndVars)
	assert.Equal(t, "testuser", test.A)
	assert.Equal(t, "testuser", test.B.B, test.B)
	assert.Equal(t, "$GITHUB_USER", test.C)
}

func TestWalkReflectStructHandlesNestedStructs(t *testing.T) {
	testStruct := &TestStruct4{
		A: "$VAR_EXAMPLE",
		Struct: &TestStruct3{
			B: "$VAR_TWO",
			C: "$VAR_THREE",
		},
	}
	os.Setenv("VAR_EXAMPLE", "value")
	os.Setenv("VAR_TWO", "2")
	os.Setenv("VAR_THREE", "true")

	Walk(testStruct, expandEndVars)

	assert.Equal(t, "value", testStruct.A)
	assert.Equal(t, "2", testStruct.Struct.B)
	assert.Equal(t, "true", testStruct.Struct.C)
}
