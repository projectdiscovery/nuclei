package installer

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/generic"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestVersionCheck(t *testing.T) {
	ignoreHash, err := NucleiVersionCheck()
	require.Nil(t, err)
	cfg := config.DefaultConfig
	if generic.EqualsAny("", ignoreHash, cfg.LatestNucleiVersion, cfg.LatestNucleiTemplatesVersion) {
		// all above values cannot be empty
		t.Errorf("something went wrong got empty response nuclei-version=%v templates-version=%v ignore-hash=%v", cfg.LatestNucleiVersion, cfg.LatestNucleiTemplatesVersion, ignoreHash)
	}
}

func TestUpdateIgnoreFileRejectsHTMLAndPreservesExisting(t *testing.T) {
	html := []byte("<!DOCTYPE HTML>\n<html>\n<head>\n<meta name=\"description\" content=\"Zscaler: blocked\">\n</head>\n</html>\n")
	withIgnoreDownload(t, http.StatusOK, html)

	cfg := config.DefaultConfig
	root := t.TempDir()
	previous := cfg.TemplatesDirectory
	t.Cleanup(func() { cfg.SetTemplatesDir(previous) })
	cfg.SetTemplatesDir(root)

	valid := []byte("tags: [weak]\nfiles: [blocked.yaml]\n")
	path := cfg.GetActiveIgnoreFilePath()
	require.NoError(t, os.WriteFile(path, valid, 0o600))

	err := UpdateIgnoreFile()
	require.Error(t, err)
	require.Contains(t, err.Error(), fmt.Sprintf("%q", path))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, valid, got)
}

func TestUpdateIgnoreFileWritesValidContents(t *testing.T) {
	payload := []byte("tags: [dos]\nfiles: [http/test.yaml]\n")
	withIgnoreDownload(t, http.StatusOK, payload)

	cfg := config.DefaultConfig
	root := t.TempDir()
	previous := cfg.TemplatesDirectory
	t.Cleanup(func() { cfg.SetTemplatesDir(previous) })
	cfg.SetTemplatesDir(root)

	require.NoError(t, UpdateIgnoreFile())

	got, err := os.ReadFile(cfg.GetActiveIgnoreFilePath())
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

func TestUpdateIgnoreFileRejectsUnexpectedStatus(t *testing.T) {
	withIgnoreDownload(t, http.StatusForbidden, []byte("tags: [weak]\n"))

	cfg := config.DefaultConfig
	root := t.TempDir()
	previous := cfg.TemplatesDirectory
	t.Cleanup(func() { cfg.SetTemplatesDir(previous) })
	cfg.SetTemplatesDir(root)

	err := UpdateIgnoreFile()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected HTTP status")
	_, statErr := os.Stat(cfg.GetActiveIgnoreFilePath())
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func withIgnoreDownload(t *testing.T, status int, body []byte) {
	t.Helper()

	previous := retryableHttpClient
	t.Cleanup(func() { retryableHttpClient = previous })

	retryableHttpClient = retryablehttp.NewClient(retryablehttp.Options{
		RetryMax: 0,
		HttpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				header := make(http.Header)
				header.Set("Content-Type", "text/plain")
				return &http.Response{
					StatusCode: status,
					Status:     http.StatusText(status),
					Body:       io.NopCloser(strings.NewReader(string(body))),
					Header:     header,
					Request:    req,
					Proto:      "HTTP/1.1",
					ProtoMajor: 1,
					ProtoMinor: 1,
				}, nil
			}),
		},
	})
}
