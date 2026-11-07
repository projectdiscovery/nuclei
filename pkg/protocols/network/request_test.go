package network

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
)

func TestNetworkExecuteWithResults(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-network"
	request := &Request{
		ID:       templateID,
		Address:  []string{"{{Hostname}}:"},
		ReadSize: 2048,
		Inputs:   []*Input{},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Name:  "test",
				Part:  "data",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"200 OK"},
			}},
			Extractors: []*extractors.Extractor{{
				Part:  "data",
				Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
				Regex: []string{"<h1>.*</h1>"},
			}},
		},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(exampleBody))
	}))
	defer ts.Close()

	parsed, err := url.Parse(ts.URL)
	require.Nil(t, err, "could not parse url")
	request.Address[0] = "{{Hostname}}"

	request.Inputs = append(request.Inputs, &Input{Data: fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", parsed.Host)})
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err = request.Compile(executerOpts)
	require.Nil(t, err, "could not compile network request")

	var finalEvent *output.InternalWrappedEvent
	t.Run("domain-valid", func(t *testing.T) {
		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)
		ctxArgs := contextargs.NewWithInput(context.Background(), parsed.Host)
		err := request.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {
			finalEvent = event
		})
		require.Nil(t, err, "could not execute network request")
	})
	require.NotNil(t, finalEvent, "could not get event output from request")
	require.Equal(t, 1, len(finalEvent.Results), "could not get correct number of results")
	require.Equal(t, "test", finalEvent.Results[0].MatcherName, "could not get correct matcher name of results")
	require.Equal(t, 1, len(finalEvent.Results[0].ExtractedResults), "could not get correct number of extracted results")
	require.Equal(t, "<h1>Example Domain</h1>", finalEvent.Results[0].ExtractedResults[0], "could not get correct extracted results")
	finalEvent = nil

	t.Run("invalid-port-override", func(t *testing.T) {
		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)
		ctxArgs := contextargs.NewWithInput(context.Background(), "127.0.0.1:11211")
		err := request.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {
			finalEvent = event
		})
		require.NotNil(t, err, "could not execute network request")
	})
	require.Nil(t, finalEvent.Results, "could not get event output from request")

	request.Inputs[0].Type = NetworkInputTypeHolder{NetworkInputType: hexType}
	request.Inputs[0].Data = hex.EncodeToString([]byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", parsed.Host)))

	t.Run("hex-to-string", func(t *testing.T) {
		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)
		ctxArgs := contextargs.NewWithInput(context.Background(), parsed.Host)
		err := request.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {
			finalEvent = event
		})
		require.Nil(t, err, "could not execute network request")
	})
	require.NotNil(t, finalEvent, "could not get event output from request")
	require.Equal(t, 1, len(finalEvent.Results), "could not get correct number of results")
	require.Equal(t, "test", finalEvent.Results[0].MatcherName, "could not get correct matcher name of results")
	require.Equal(t, 1, len(finalEvent.Results[0].ExtractedResults), "could not get correct number of extracted results")
	require.Equal(t, "<h1>Example Domain</h1>", finalEvent.Results[0].ExtractedResults[0], "could not get correct extracted results")
}

func captureNetworkRequest(t *testing.T, listener net.Listener) (<-chan string, <-chan error) {
	t.Helper()
	captured := make(chan string, 1)
	serverErr := make(chan error, 1)

	go func() {
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			_ = tcpListener.SetDeadline(time.Now().Add(5 * time.Second))
		}

		for {
			conn, err := listener.Accept()
			if err != nil {
				serverErr <- err
				return
			}

			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			buffer := make([]byte, 4096)
			n, err := conn.Read(buffer)
			if err != nil {
				_ = conn.Close()
				if err == io.EOF {
					continue
				}
				serverErr <- err
				return
			}
			captured <- string(buffer[:n])
			_, _ = conn.Write([]byte("ok"))
			_ = conn.Close()
			return
		}
	}()

	return captured, serverErr
}

func TestNetworkGeneratorPayloadInteractshMarkerRendersBeforeInput(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.InteractionsCoolDownPeriod = 0
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "could not listen")
	t.Cleanup(func() {
		_ = listener.Close()
	})

	captured, serverErr := captureNetworkRequest(t, listener)

	request := &Request{
		ID:       "network-payload-interactsh",
		Address:  []string{"{{Hostname}}"},
		ReadSize: 2,
		Threads:  1,
		Inputs: []*Input{{
			Data: "{{payload}}",
		}},
		Payloads: map[string]interface{}{
			"payload": []string{"{{interactsh-url}}"},
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: "network-payload-interactsh",
	})
	client, err := interactsh.New(&interactsh.Options{
		ServerURL:           options.InteractshURL,
		CacheSize:           options.InteractionsCacheSize,
		Eviction:            time.Duration(options.InteractionsEviction) * time.Second,
		CooldownPeriod:      time.Duration(options.InteractionsCoolDownPeriod) * time.Second,
		PollDuration:        time.Duration(options.InteractionsPollDuration) * time.Second,
		DisableHttpFallback: true,
	})
	require.NoError(t, err, "could not create interactsh client")
	t.Cleanup(func() {
		client.Close()
	})
	executerOpts.Interactsh = client

	require.NoError(t, request.Compile(executerOpts))

	ctxArgs := contextargs.NewWithInput(context.Background(), listener.Addr().String())
	err = request.ExecuteWithResults(ctxArgs, nil, nil, func(*output.InternalWrappedEvent) {})
	require.NoError(t, err, "could not execute network request")

	select {
	case got := <-captured:
		require.NotContains(t, got, "{{payload}}")
		require.NotContains(t, got, "{{interactsh-url}}")
		require.Contains(t, got, client.GetHostname())
	case err := <-serverErr:
		require.NoError(t, err, "server failed")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for network request")
	}
}

func TestNetworkCompileDefersInteractshMarkerHelpersToRuntime(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.InteractionsCoolDownPeriod = 0
	testutils.Init(options)
	t.Cleanup(func() {
		testutils.Cleanup(options)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "could not listen")
	t.Cleanup(func() {
		_ = listener.Close()
	})

	captured, serverErr := captureNetworkRequest(t, listener)

	request := &Request{
		ID:       "network-runtime-interactsh-helper",
		Address:  []string{"{{Hostname}}"},
		ReadSize: 2,
		Threads:  1,
		Inputs: []*Input{{
			Data: "{{md5('{{interactsh-url}}')}}",
		}},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: "network-runtime-interactsh-helper",
	})
	client, err := interactsh.New(&interactsh.Options{
		ServerURL:           options.InteractshURL,
		CacheSize:           options.InteractionsCacheSize,
		Eviction:            time.Duration(options.InteractionsEviction) * time.Second,
		CooldownPeriod:      time.Duration(options.InteractionsCoolDownPeriod) * time.Second,
		PollDuration:        time.Duration(options.InteractionsPollDuration) * time.Second,
		DisableHttpFallback: true,
	})
	require.NoError(t, err, "could not create interactsh client")
	t.Cleanup(func() {
		client.Close()
	})
	executerOpts.Interactsh = client

	require.NoError(t, request.Compile(executerOpts))

	ctxArgs := contextargs.NewWithInput(context.Background(), listener.Addr().String())
	err = request.ExecuteWithResults(ctxArgs, nil, nil, func(*output.InternalWrappedEvent) {})
	require.NoError(t, err, "could not execute network request")

	literalMarkerHash := fmt.Sprintf("%x", md5.Sum([]byte("{{interactsh-url}}")))
	select {
	case got := <-captured:
		require.Len(t, got, len(literalMarkerHash))
		require.NotEqual(t, literalMarkerHash, got, "compile-time evaluation must not consume the source marker before runtime Interactsh allocation")
		require.NotContains(t, got, "{{interactsh-url}}")
	case err := <-serverErr:
		require.NoError(t, err, "server failed")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for network request")
	}
}

var exampleBody = `<!doctype html>
<html>
<head>
    <title>Example Domain</title>

    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
        
    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 2em;
        background-color: #fdfdff;
        border-radius: 0.5em;
        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        div {
            margin: 0 auto;
            width: auto;
        }
    }
    </style>    
</head>

<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>
`
