package installer

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	"github.com/projectdiscovery/retryablehttp-go"
	updateutils "github.com/projectdiscovery/utils/update"
)

const (
	pdtmNucleiVersionEndpoint    = "https://api.pdtm.sh/api/v1/tools/nuclei"
	pdtmNucleiIgnoreFileEndpoint = "https://api.pdtm.sh/api/v1/tools/nuclei/ignore"
)

// defaultHttpClient is http client that is only meant to be used for version check
// if proxy env variables are set those are reflected in this client
var retryableHttpClient = retryablehttp.NewClient(retryablehttp.Options{HttpClient: updateutils.DefaultHttpClient, RetryMax: 2})

// PdtmAPIResponse is the response from pdtm API for nuclei endpoint
type PdtmAPIResponse struct {
	IgnoreHash string `json:"ignore-hash"`
	Tools      []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"tools"`
}

// NucleiVersionCheck checks for the latest version of nuclei and nuclei templates
// and returns an error if it fails to check on success it returns nil and changes are
// made to the default config in config.DefaultConfig
func NucleiVersionCheck() error {
	return doVersionCheck(false)
}

// this will be updated by features of 1.21 release (which directly provides sync.Once(func()))
type sdkUpdateCheck struct {
	sync.Once
}

var sdkUpdateCheckInstance = &sdkUpdateCheck{}

// NucleiSDKVersionCheck checks for latest version of nuclei which running in sdk mode
// this only happens once per process regardless of how many times this function is called
func NucleiSDKVersionCheck() {
	sdkUpdateCheckInstance.Do(func() {
		_ = doVersionCheck(true)
	})
}

// getpdtmParams returns encoded query parameters sent to update check endpoint
func getpdtmParams(isSDK bool) string {
	values, err := url.ParseQuery(updateutils.GetpdtmParams(config.Version))
	if err != nil {
		gologger.Verbose().Msgf("error parsing update check params: %v", err)
		return updateutils.GetpdtmParams(config.Version)
	}
	if isSDK {
		values.Add("sdk", "true")
	}
	return values.Encode()
}

// UpdateIgnoreFile updates default ignore file by downloading latest ignore file
func UpdateIgnoreFile() error {
	resp, err := retryableHttpClient.Get(pdtmNucleiIgnoreFileEndpoint + "?" + getpdtmParams(false))
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code %d while downloading nuclei-ignore file", resp.StatusCode)
	}
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := writeNucleiIgnoreFile(config.DefaultConfig.GetIgnoreFilePath(), bin); err != nil {
		return err
	}
	return config.DefaultConfig.UpdateNucleiIgnoreHash()
}

func writeNucleiIgnoreFile(path string, data []byte) error {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("invalid nuclei-ignore file: %w", err)
	}
	_, hasTags := raw["tags"]
	_, hasFiles := raw["files"]
	if !hasTags && !hasFiles {
		return fmt.Errorf("invalid nuclei-ignore file: missing tags or files")
	}

	var ignore config.IgnoreFile
	if err := yaml.Unmarshal(data, &ignore); err != nil {
		return fmt.Errorf("invalid nuclei-ignore file: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func doVersionCheck(isSDK bool) error {
	// we use global retryablehttp client so its not immediately gc'd if any references are held
	// and according our config we have idle connections which are shown as leaked by goleak in tests
	// i.e we close all idle connections after our use and it doesn't affect any other part of the code
	defer retryableHttpClient.HTTPClient.CloseIdleConnections()

	resp, err := retryableHttpClient.Get(pdtmNucleiVersionEndpoint + "?" + getpdtmParams(isSDK))
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var pdtmResp PdtmAPIResponse
	if err := json.Unmarshal(bin, &pdtmResp); err != nil {
		return err
	}
	var nucleiversion, templateversion string
	for _, tool := range pdtmResp.Tools {
		switch tool.Name {
		case "nuclei":
			if tool.Version != "" {
				nucleiversion = "v" + tool.Version
			}

		case "nuclei-templates":
			if tool.Version != "" {
				templateversion = "v" + tool.Version
			}
		}
	}
	return config.DefaultConfig.WriteVersionCheckData(pdtmResp.IgnoreHash, nucleiversion, templateversion)
}
