package runner

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	yamlwrapper "github.com/projectdiscovery/nuclei/v2/pkg/utils/yaml"
	"github.com/projectdiscovery/retryablehttp-go"
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

func Test_assignEnvVarToReportingOptSuccess(t *testing.T) {
	data := `
github:
  username: $GITHUB_USER
  owner: $GITHUB_OWNER
  token: $GITHUB_TOKEN
  project-name: $GITHUB_PROJECT
  issue-label: $ISSUE_LABEL
  severity-as-label: false`

	header := http.Header{}
	header.Add("test", "test")

	reportingOptions := &reporting.Options{
		HttpClient: &retryablehttp.Client{
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					ProxyConnectHeader: header,
				},
			},
		},
	}
	err := yamlwrapper.DecodeAndValidate(strings.NewReader(data), reportingOptions)
	require.Nil(t, err)

	os.Setenv("GITHUB_USER", "testuser")

	Walk(reportingOptions, "yaml", AssignEnvVarsToFields)
	assert.Equal(t, "testuser", reportingOptions.GitHub.Username)
}

func Test_assignEnvVarToReportingOptSuccessMultiple(t *testing.T) {
	data := `
github:
  username: $GITHUB_USER
  owner: $GITHUB_OWNER
  token: $GITHUB_TOKEN
  project-name: $GITHUB_PROJECT
  issue-label: $ISSUE_LABEL
  severity-as-label: false`

	header := http.Header{}
	header.Add("test", "test")

	reportingOptions := &reporting.Options{
		HttpClient: &retryablehttp.Client{
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					ProxyConnectHeader: header,
				},
			},
		},
	}
	err := yamlwrapper.DecodeAndValidate(strings.NewReader(data), reportingOptions)
	require.Nil(t, err)

	os.Setenv("GITHUB_USER", "testuser")
	os.Setenv("GITHUB_TOKEN", "tokentesthere")
	os.Setenv("GITHUB_PROJECT", "testproject")

	Walk(reportingOptions, "yaml", AssignEnvVarsToFields)
	assert.Equal(t, "testuser", reportingOptions.GitHub.Username)
	assert.Equal(t, "tokentesthere", reportingOptions.GitHub.Token)
	assert.Equal(t, "testproject", reportingOptions.GitHub.ProjectName)
}

func Test_assignEnvVarToReportingOptEmptyField(t *testing.T) {
	data := `
github:
  username: ""
  owner: $GITHUB_OWNER
  token: $GITHUB_TOKEN
  project-name: $GITHUB_PROJECT
  issue-label: $ISSUE_LABEL
  severity-as-label: false`

	header := http.Header{}
	header.Add("test", "test")

	reportingOptions := &reporting.Options{
		HttpClient: &retryablehttp.Client{
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					ProxyConnectHeader: header,
				},
			},
		},
	}
	err := yamlwrapper.DecodeAndValidate(strings.NewReader(data), reportingOptions)
	require.NotNil(t, err)
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

func TestWalkReflectStructAssignsEnvVars(t *testing.T) {
	testStruct := &TestStruct1{
		A: "$VAR_EXAMPLE",
		Struct: &TestStruct2{
			B: "$VAR_TWO",
		},
	}
	os.Setenv("VAR_EXAMPLE", "value")
	os.Setenv("VAR_TWO", "value2")

	Walk(testStruct, "yaml", AssignEnvVarsToFields)

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

	Walk(testStruct, "yaml", AssignEnvVarsToFields)

	assert.Equal(t, "value", testStruct.A)
	assert.Equal(t, "2", testStruct.B)
	assert.Equal(t, "true", testStruct.C)
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

	Walk(testStruct, "yaml", AssignEnvVarsToFields)

	assert.Equal(t, "value", testStruct.A)
	assert.Equal(t, "2", testStruct.Struct.B)
	assert.Equal(t, "true", testStruct.Struct.C)
}
