package updatecheck

import (
	"io"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/retryablehttp-go"
)

const (
	RegisterServer = "https://version-check.nuclei.sh/"
	VersionsCall   = "versions"
	IgnoreCall     = "ignore"
)

// LatestVersion is the latest version info for nuclei and templates repos
type LatestVersion struct {
	Nuclei     string
	Templates  string
	IgnoreHash string
}

// GetLatestNucleiTemplatesVersion returns the latest version info for nuclei and templates repos
func GetLatestNucleiTemplatesVersion() (*LatestVersion, error) {
	resp, err := retryablehttp.DefaultClient().Get(RegisterServer + VersionsCall)
	if err != nil {
		return nil, err
	}

	data := make(map[string]string)
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return &LatestVersion{Nuclei: data["nuclei"], Templates: data["templates"], IgnoreHash: data["ignore-hash"]}, nil
}

// GetLatestIgnoreFile returns the latest version of nuclei ignore
func GetLatestIgnoreFile() ([]byte, error) {
	resp, err := retryablehttp.DefaultClient().Get(RegisterServer + VersionsCall)
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}
