package testing

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func Test_Proxy_Template(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)

	pairs, err := doIntercept()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Intercepted: %+v\n", len(pairs))

	tmpl := &NucleiTestTemplate{
		Requests:   pairs,
		TemplateID: "test-template",
	}
	handler, err := tmpl.MockServer()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid_mock_server", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "http://scanme.sh/demo", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Custom-Header", "myvalue")
		handler.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
	})
	t.Run("invalid_mock_server", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "http://scanme.sh/", nil)
		if err != nil {
			t.Fatal(err)
		}
		handler.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != 404 {
			t.Fatalf("expected 404, got %d", resp.StatusCode)
		}
	})
}

func doIntercept() ([]RequestResponsePair, error) {
	ps, err := NewProxyServer()
	if err != nil {
		return nil, err
	}
	defer ps.Close()

	// Make a http request by using the proxy server
	// and check the intercepted requests and responses
	// to see if the request was intercepted and correctly
	// logged.
	req, err := http.NewRequest("GET", "http://scanme.sh/demo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Custom-Header", "myvalue")

	proxyURL := "http://" + ps.ListenAddr
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Proxy URL: %s\n", parsed.String())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(parsed),
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	intercepted := ps.Intercepted()
	if len(intercepted) == 0 {
		return nil, fmt.Errorf("no requests were intercepted")
	}
	return intercepted, nil
}
