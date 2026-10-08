package http

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/utils/errkit"
)

// newReplayClient builds the client that re-sends findings through proxy.
func newReplayClient(proxy string, timeout time.Duration) (*http.Client, error) {
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return nil, errkit.Wrapf(err, "invalid replay proxy %q", proxy)
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			// scan targets and intercepting proxies present untrusted certificates
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		// the proxy must record the request that matched, not where it redirects
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// replayRequest re-sends a request that produced a finding through the replay
// proxy, so it lands in a tool such as Burp without routing the whole scan
// through it. The response is discarded and failures are only logged: a replay
// must never affect the scan.
func (request *Request) replayRequest(dumpedRequest []byte, formedURL string) {
	if request.replayClient == nil {
		return
	}
	dump := bufio.NewReader(bytes.NewReader(dumpedRequest))
	replay, err := http.ReadRequest(dump)
	if err != nil {
		gologger.Debug().Msgf("[%s] could not parse request to replay: %s", request.options.TemplateID, err)
		return
	}
	// unsafe raw requests are dumped as written and may carry a body without
	// declaring its length; ReadRequest would then treat them as bodyless
	if replay.ContentLength <= 0 && len(replay.TransferEncoding) == 0 {
		if rest, _ := io.ReadAll(dump); len(rest) > 0 {
			replay.Body = io.NopCloser(bytes.NewReader(rest))
			replay.ContentLength = int64(len(rest))
		}
	}
	target, err := url.Parse(formedURL)
	if err != nil {
		gologger.Debug().Msgf("[%s] could not parse URL to replay %q: %s", request.options.TemplateID, formedURL, err)
		return
	}
	replay.RequestURI = ""
	replay.URL = target

	resp, err := request.replayClient.Do(replay)
	if err != nil {
		gologger.Debug().Msgf("[%s] could not replay %s through %s: %s", request.options.TemplateID, formedURL, request.options.Options.ReplayProxy, err)
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
