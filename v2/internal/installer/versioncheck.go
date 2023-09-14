package installer

import (
	"encoding/json"
	"io"
	"net/url"
	"os"
	"runtime"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
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
	resp, err := retryableHttpClient.Get(pdtmNucleiVersionEndpoint + "?" + getpdtmParams())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
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

// getpdtmParams returns encoded query parameters sent to update check endpoint
func getpdtmParams() string {
	params := &url.Values{}
	params.Add("os", runtime.GOOS)
	params.Add("arch", runtime.GOARCH)
	params.Add("go_version", runtime.Version())
	params.Add("v", config.Version)
	params.Add("utm_source", getUtmSource())
	return params.Encode()
}

// UpdateIgnoreFile updates default ignore file by downloading latest ignore file
func UpdateIgnoreFile() error {
	resp, err := retryableHttpClient.Get(pdtmNucleiIgnoreFileEndpoint + "?" + getpdtmParams())
	if err != nil {
		return err
	}
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := os.WriteFile(config.DefaultConfig.GetIgnoreFilePath(), bin, 0644); err != nil {
		return err
	}
	return config.DefaultConfig.UpdateNucleiIgnoreHash()
}
