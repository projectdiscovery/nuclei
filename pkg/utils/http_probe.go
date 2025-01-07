package utils

import (
	"fmt"
	"net/http"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/useragent"
)

var (
	HttpSchemes = []string{"https", "http"}
)

// ProbeURL probes the scheme for a URL. first HTTPS is tried
// and if any errors occur http is tried. If none succeeds, probing
// is abandoned for such URLs.
func ProbeURL(input string, httpxclient *httpx.HTTPX) string {
	for _, scheme := range HttpSchemes {
		formedURL := fmt.Sprintf("%s://%s", scheme, input)
		req, err := httpxclient.NewRequest(http.MethodHead, formedURL)
		if err != nil {
			continue
		}
		userAgent := useragent.PickRandom()
		req.Header.Set("User-Agent", userAgent.Raw)

		if _, err = httpxclient.Do(req, httpx.UnsafeOptions{}); err != nil {
			continue
		}

		return formedURL
	}
	return ""
}

type inputLivenessChecker struct {
	client *httpx.HTTPX
}

// ProbeURL probes the scheme for a URL. first HTTPS is tried
func (i *inputLivenessChecker) ProbeURL(input string) (string, error) {
	return ProbeURL(input, i.client), nil
}

func (i *inputLivenessChecker) Close() error {
	if i.client.Dialer != nil {
		i.client.Dialer.Close()
	}
	return nil
}

// GetInputLivenessChecker returns a new input liveness checker using provided httpx client
func GetInputLivenessChecker(client *httpx.HTTPX) types.InputLivenessProbe {
	x := &inputLivenessChecker{client: client}
	return x
}
