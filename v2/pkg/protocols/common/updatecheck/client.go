package updatecheck

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/retryablehttp-go"
)

const (
	RegisterServer = "https://version-check.nuclei.sh/"
	VersionsCall   = "versions"
	IgnoreCall     = "ignore"
)

var nucleiVersion string

// LatestVersion is the latest version info for nuclei and templates repos
type LatestVersion struct {
	Nuclei     string
	Templates  string
	IgnoreHash string
}

func InitNucleiVersion(version string) {
	nucleiVersion = version
}

// GetLatestNucleiTemplatesVersion returns the latest version info for nuclei and templates repos
func GetLatestNucleiTemplatesVersion() (*LatestVersion, error) {
	body, err := callRegisterServer(VersionsCall)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	data := make(map[string]string)
	if err := jsoniter.NewDecoder(body).Decode(&data); err != nil {
		return nil, err
	}
	return &LatestVersion{Nuclei: data["nuclei"], Templates: data["templates"], IgnoreHash: data["ignore-hash"]}, nil
}

// GetLatestIgnoreFile returns the latest version of nuclei ignore
func GetLatestIgnoreFile() ([]byte, error) {
	body, err := callRegisterServer(IgnoreCall)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// callRegisterServer makes a request to RegisterServer with a call.
func callRegisterServer(call string) (io.ReadCloser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, RegisterServer+call, nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not make request")
	}
	if nucleiVersion != "" {
		query := make(url.Values, 1)
		query.Set("v", nucleiVersion)
		req.URL.RawQuery = query.Encode()
	}
	resp, err := retryablehttp.DefaultClient().Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "could not do request")
	}
	return resp.Body, nil
}
