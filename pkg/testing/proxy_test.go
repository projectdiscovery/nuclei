package testing

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func Test_Proxy(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)

	ps, err := NewProxyServer()
	if err != nil {
		t.Fatal(err)
	}

	// Make a http request by using the proxy server
	// and check the intercepted requests and responses
	// to see if the request was intercepted and correctly
	// logged.
	var jsonStr = []byte(`{"title":"Buy cheese and bread for breakfast."}`)
	req, err := http.NewRequest("POST", "http://scanme.sh", bytes.NewBuffer(jsonStr))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Custom-Header", "myvalue")
	req.Header.Set("Content-Type", "application/json")

	proxyURL := "http://" + ps.ListenAddr
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Proxy URL: %s\n", parsed.String())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(parsed),
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = data
	ps.Close()

	intercepted := ps.Intercepted()
	if len(intercepted) == 0 {
		t.Fatal("no intercepted requests")
	}
	fmt.Printf("Intercepted: %+v\n", intercepted)

}
