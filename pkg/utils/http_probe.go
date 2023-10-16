package utils

import (
	"fmt"
	"net/http"

	"github.com/corpix/uarand"
	"github.com/projectdiscovery/httpx/common/httpx"
)

var (
	HttpSchemes = []string{"https", "http"}
)

// probeURL probes the scheme for a URL. first HTTPS is tried
// and if any errors occur http is tried. If none succeeds, probing
// is abandoned for such URLs.
func ProbeURL(input string, httpxclient *httpx.HTTPX) string {
	for _, scheme := range HttpSchemes {
		formedURL := fmt.Sprintf("%s://%s", scheme, input)
		req, err := httpxclient.NewRequest(http.MethodHead, formedURL)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", uarand.GetRandom())

		if _, err = httpxclient.Do(req, httpx.UnsafeOptions{}); err != nil {
			continue
		}
		return formedURL
	}
	return ""
}
