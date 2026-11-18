package splunk

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

type bodyCloseTransport func(*http.Request) (*http.Response, error)

func (f bodyCloseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read interrupted") }

func TestExportClosesResponseBody(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		reader    io.Reader
		wantError bool
	}{
		{"success", http.StatusOK, strings.NewReader("{}"), false},
		{"server error", http.StatusInternalServerError, strings.NewReader("unavailable"), true},
		{"read error", http.StatusOK, errorReader{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &trackedBody{Reader: tc.reader}
			e := &Exporter{url: "http://report.invalid/services/collector/event", splunk: &http.Client{Transport: bodyCloseTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: body, Header: make(http.Header)}, nil
			})}}
			err := e.Export(&output.ResultEvent{})
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.True(t, body.closed, "exporter must close the response body")
		})
	}
}
