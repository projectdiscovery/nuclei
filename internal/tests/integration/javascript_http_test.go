//go:build integration
// +build integration

package integration_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
)

// startJSHTTPServer starts a local HTTP server exercising the generic paths
// used by the nuclei/http javascript integration templates.
func startJSHTTPServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "ok")
		_, _ = io.WriteString(w, "hello")
	})
	mux.HandleFunc("/echo-header", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("X-Token"))
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/set-cookie", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc"})
		_, _ = io.WriteString(w, "set")
	})
	mux.HandleFunc("/echo-cookie", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sid")
		if err != nil || c.Value != "abc" {
			_, _ = io.WriteString(w, "missing")
			return
		}
		_, _ = io.WriteString(w, "sid-ok")
	})
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/land", http.StatusFound)
	})
	mux.HandleFunc("/land", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "landed")
	})
	return httptest.NewServer(mux)
}

type javascriptHTTPGet struct{}

func (j *javascriptHTTPGet) Execute(filePath string) error {
	ts := startJSHTTPServer()
	defer ts.Close()

	// Target as host:port so javascript Host/Port args populate cleanly.
	hostPort := strings.TrimPrefix(ts.URL, "http://")
	results, err := runSignedNucleiTemplateAndGetResults(filePath, hostPort, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type javascriptHTTPClientFlow struct{}

func (j *javascriptHTTPClientFlow) Execute(filePath string) error {
	ts := startJSHTTPServer()
	defer ts.Close()

	hostPort := strings.TrimPrefix(ts.URL, "http://")
	results, err := runSignedNucleiTemplateAndGetResults(filePath, hostPort, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type javascriptHTTPDenied struct{}

func (j *javascriptHTTPDenied) Execute(filePath string) error {
	results, err := runSignedNucleiTemplateAndGetResults(filePath, "127.0.0.1", debug, "-eh", "203.0.113.10")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}
