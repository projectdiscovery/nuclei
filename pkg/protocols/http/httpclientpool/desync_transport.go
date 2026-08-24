package httpclientpool

import (
	"fmt"
	"net/http"
	"net/http/httptrace"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// DesyncError identifies a host whose reused HTTP/1.x connection returned an
// implausibly early response.
type DesyncError struct {
	Host string
}

func (e *DesyncError) Error() string {
	return fmt.Sprintf("response for %s arrived before a network round trip", e.Host)
}

// desyncDetectingTransport observes each RoundTrip separately, including every
// redirect hop. This is important because http.Client may otherwise hide the
// response that triggered a redirect before the caller can inspect it.
type desyncDetectingTransport struct {
	base      http.RoundTripper
	enabled   bool
	baselines *protocolstate.ExpiringDurationMap
}

func (t *desyncDetectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.enabled {
		return t.base.RoundTrip(req)
	}

	probe := NewDesyncProbe(req.URL.Host, t.baselines)
	traced := req.WithContext(httptrace.WithClientTrace(req.Context(), probe.Trace()))
	resp, err := t.base.RoundTrip(traced)
	if err != nil || resp == nil || resp.ProtoMajor != 1 || !probe.Suspect() {
		return resp, err
	}

	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	t.CloseIdleConnections()
	return nil, &DesyncError{Host: desyncedHostKey(req.URL.Host)}
}

func (t *desyncDetectingTransport) CloseIdleConnections() {
	type closeIdler interface{ CloseIdleConnections() }
	if closer, ok := t.base.(closeIdler); ok {
		closer.CloseIdleConnections()
	}
}
