package runner

import (
	"log"
	"net/http"
	"os"
	"reflect"
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

	log.Printf("%#v\n", reportingOptions.GitHub)
	val := reflect.ValueOf(*reportingOptions)
	assignEnvVarToReportingOpt(val)
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

	log.Printf("%#v\n", reportingOptions.GitHub)
	val := reflect.ValueOf(*reportingOptions)
	assignEnvVarToReportingOpt(val)
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

func Test_assignEnvVarToReportingOptFailed(t *testing.T) {
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

	log.Printf("%#v\n", reportingOptions.GitHub)
	val := reflect.ValueOf(*reportingOptions)
	assignEnvVarToReportingOpt(val)
	assert.NotEqual(t, "$GITHUB_USER", reportingOptions.GitHub.Username)
}

func Test_assignEnvVarToReportingOptFailedMultiple(t *testing.T) {
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
	os.Setenv("GITHUB_PROJECT", "testproject")

	log.Printf("%#v\n", reportingOptions.GitHub)
	val := reflect.ValueOf(*reportingOptions)
	assignEnvVarToReportingOpt(val)
	assert.Equal(t, "testuser", reportingOptions.GitHub.Username)
	assert.NotEqual(t, "$GITHUB_PROJECT", reportingOptions.GitHub.Username)
}
