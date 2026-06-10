package utils

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/useragent"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

var commonHttpPorts = []string{
	"80",
	"8080",
}
var defaultHttpSchemes = []string{
	"https",
	"http",
}
var httpFirstSchemes = []string{
	"http",
	"https",
}

// determineSchemeOrder for the input
func determineSchemeOrder(input string) []string {
	if _, port, err := net.SplitHostPort(input); err == nil {
		// if input has port that is commonly used for HTTP, return http then https
		if sliceutil.Contains(commonHttpPorts, port) {
			return httpFirstSchemes
		}

		// As of 10/2025 shodan shows that ports > 1024 are more likely to expose HTTP
		// hence we test first http then https on higher ports
		// if input has port > 1024, return http then https
		if port, err := strconv.Atoi(port); err == nil && port > 1024 {
			return httpFirstSchemes
		}
	}

	return defaultHttpSchemes
}

// ProbeURL probes the scheme for a URL.
// http schemes are selected with heuristics
// If none succeeds, probing is abandoned for such URLs.
func ProbeURL(input string, httpxclient *httpx.HTTPX) string {
	normalizedInput := normalizeProbeInput(input)
	schemes := determineSchemeOrder(normalizedInput)
	for _, scheme := range schemes {
		formedURL := fmt.Sprintf("%s://%s", scheme, normalizedInput)
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

// normalizeProbeInput rewrites unbracketed IPv6 literals to bracketed host form.
func normalizeProbeInput(input string) string {
	if strings.Contains(input, "://") || strings.HasPrefix(input, "[") {
		return input
	}
	addr, err := netip.ParseAddr(input)
	if err != nil || !addr.Is6() {
		return input
	}
	return fmt.Sprintf("[%s]", addr.String())
}

type inputLivenessChecker struct {
	client *httpx.HTTPX
}

// ProbeURL probes the scheme for a URL.
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
