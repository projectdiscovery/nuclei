//go:build integration
// +build integration

package integration_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	osutils "github.com/projectdiscovery/utils/os"
)

// All Interactsh related testcases
var interactshTestCases = []integrationCase{
	{Path: "protocols/http/interactsh.yaml", TestCase: &httpInteractshRequest{}, DisableOn: func() bool { return osutils.IsWindows() || osutils.IsOSX() }},
	{Path: "protocols/http/interactsh-with-payloads.yaml", TestCase: &httpInteractshWithPayloadsRequest{}, DisableOn: func() bool { return true }},
	{Path: "protocols/http/interactsh-stop-at-first-match.yaml", TestCase: &httpInteractshStopAtFirstMatchRequest{}, DisableOn: func() bool { return true }}, // disable this test for now
	{Path: "protocols/http/default-matcher-condition.yaml", TestCase: &httpDefaultMatcherCondition{}, DisableOn: func() bool { return true }},
	{Path: "protocols/http/interactsh-requests-mc-and.yaml", TestCase: &httpInteractshRequestsWithMCAnd{}},
	{Path: "protocols/http/interactsh-feed.yaml", TestCase: &httpInteractshFeedRequest{}},
}

const (
	feedCorrelationID = "c0ffee00c0ffee00c0ff"
	feedDomain        = "oob.example"
)

type httpInteractshFeedRequest struct{}

// Execute runs nuclei in feed mode with no interactsh server: the target
// stands in for the registration's owner and appends to the feed an
// interaction for the URL nuclei sent it.
func (h *httpInteractshFeedRequest) Execute(filePath string) error {
	feed, err := os.CreateTemp("", "nuclei-interactsh-feed-*.jsonl")
	if err != nil {
		return err
	}
	feedPath := feed.Name()
	_ = feed.Close()
	defer func() { _ = os.Remove(feedPath) }()

	handlerErr := &capturedError{}
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		host := strings.TrimPrefix(r.Header.Get("url"), "http://")
		label, ok := strings.CutSuffix(host, "."+feedDomain)
		if !ok || !strings.HasPrefix(label, feedCorrelationID) {
			handlerErr.Set(fmt.Errorf("interaction url %q is not under the feed registration", host))
			return
		}
		line, err := json.Marshal(map[string]string{
			"protocol":       "http",
			"unique-id":      label,
			"full-id":        label,
			"raw-request":    "GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Feed-Owner: integration\r\n\r\n",
			"remote-address": "127.0.0.1",
			"timestamp":      time.Now().UTC().Format(time.RFC3339Nano),
		})
		if err != nil {
			handlerErr.Set(err)
			return
		}
		file, err := os.OpenFile(feedPath, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			handlerErr.Set(err)
			return
		}
		defer func() { _ = file.Close() }()
		_, err = file.Write(append(line, '\n'))
		handlerErr.Set(err)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug,
		"-interactsh-correlation-id", feedCorrelationID,
		"-interactsh-domain", feedDomain,
		"-interactsh-feed", feedPath,
	)
	if err != nil {
		return err
	}
	if err := handlerErr.Err(); err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}
