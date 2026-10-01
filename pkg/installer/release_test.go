package installer

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// fakeTemplateRelease serves an in-memory nuclei-templates release in place of
// the GitHub API, so tests run the real downloader without fetching the actual
// repository, which cost several minutes per test on windows.
type fakeTemplateRelease struct {
	version string
	files   map[string]string
}

const fakeZipballURL = "https://api.github.com/repos/projectdiscovery/nuclei-templates/zipball/fake"

func (r fakeTemplateRelease) RoundTrip(req *http.Request) (*http.Response, error) {
	switch {
	case strings.HasSuffix(req.URL.Path, "/releases/latest"):
		body, err := json.Marshal(map[string]string{"tag_name": r.version, "zipball_url": fakeZipballURL})
		if err != nil {
			return nil, err
		}
		return fakeResponse(req, "application/json", body), nil
	case req.URL.String() == fakeZipballURL:
		body, err := r.zipball()
		if err != nil {
			return nil, err
		}
		return fakeResponse(req, "application/zip", body), nil
	}
	return nil, fmt.Errorf("unexpected request to %s", req.URL)
}

func (r fakeTemplateRelease) zipball() ([]byte, error) {
	names := make([]string, 0, len(r.files))
	for name := range r.files {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	archive := zip.NewWriter(&buf)
	for _, name := range names {
		// a github zipball nests every entry under one root directory
		header := &zip.FileHeader{Name: "projectdiscovery-nuclei-templates-test/" + name, Method: zip.Deflate}
		header.SetMode(0o644)
		w, err := archive.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err := io.WriteString(w, r.files[name]); err != nil {
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func fakeResponse(req *http.Request, contentType string, body []byte) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {contentType}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// useTemplateRelease routes the installer's GitHub requests to release for the
// rest of the test. The downloader builds its client without a transport, so
// swapping http.DefaultTransport reaches it; tests calling this must not run in
// parallel.
func useTemplateRelease(t *testing.T, release fakeTemplateRelease) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = release
	t.Cleanup(func() { http.DefaultTransport = previous })
}
