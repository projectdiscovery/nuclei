package httpclientpool

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/retryablehttp-go"
)

func delayedTracedDial(delay time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		trace := httptrace.ContextClientTrace(ctx)
		if trace != nil && trace.ConnectStart != nil {
			trace.ConnectStart(network, address)
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		conn, err := net.DialTimeout(network, address, time.Second)
		if trace != nil && trace.ConnectDone != nil {
			trace.ConnectDone(network, address, err)
		}
		return conn, err
	}
}

func TestDesyncTransportDetectsExtraResponseOnReusedSocket(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer func() { _ = conn.Close() }()
		reader := bufio.NewReader(conn)
		for requestNumber := 1; requestNumber <= 2; requestNumber++ {
			req, readErr := http.ReadRequest(reader)
			if readErr != nil {
				serverDone <- readErr
				return
			}
			_ = req.Body.Close()
			if requestNumber == 1 {
				_, readErr = fmt.Fprint(conn,
					"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1")
			} else {
				// This valid response belongs to the first request but arrives only
				// after net/http has reused the socket for the second one.
				_, readErr = fmt.Fprint(conn,
					"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Response: stale\r\n\r\nS"+
						"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Response: fresh\r\n\r\nF")
			}
			if readErr != nil {
				serverDone <- readErr
				return
			}
		}
		serverDone <- nil
	}()

	baselines := protocolstate.NewExpiringDurationMap(time.Minute)
	transport := &http.Transport{
		MaxIdleConnsPerHost: 1,
		DialContext:         delayedTracedDial(100 * time.Millisecond),
	}
	client := &http.Client{Transport: &desyncDetectingTransport{
		base: transport, enabled: true, baselines: baselines,
	}}
	t.Cleanup(client.CloseIdleConnections)

	url := "http://" + listener.Addr().String()
	first, err := client.Get(url)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, first.Body)
	require.NoError(t, err)
	require.NoError(t, first.Body.Close())

	second, err := client.Get(url)
	require.Nil(t, second)
	var desyncErr *DesyncError
	require.ErrorAs(t, err, &desyncErr)
	require.Equal(t, listener.Addr().String(), desyncErr.Host)
	require.NoError(t, <-serverDone)
}

func TestDesyncTransportAllowsHealthyReusedSocket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(60 * time.Millisecond)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(server.Close)

	baselines := protocolstate.NewExpiringDurationMap(time.Minute)
	transport := &http.Transport{
		MaxIdleConnsPerHost: 1,
		DialContext:         delayedTracedDial(100 * time.Millisecond),
	}
	client := &http.Client{Transport: &desyncDetectingTransport{
		base: transport, enabled: true, baselines: baselines,
	}}
	t.Cleanup(client.CloseIdleConnections)

	first, err := client.Get(server.URL)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, first.Body)
	require.NoError(t, err)
	require.NoError(t, first.Body.Close())

	var reused atomic.Bool
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) },
	}))
	second, err := client.Do(req)
	require.NoError(t, err)
	require.True(t, reused.Load())
	body, err := io.ReadAll(second.Body)
	require.NoError(t, err)
	require.Equal(t, "ok", string(body))
	require.NoError(t, second.Body.Close())
}

type scriptedRoundTripper struct {
	steps     []func(*http.Request) (*http.Response, error)
	calls     atomic.Int64
	closeIdle atomic.Int64
}

func (s *scriptedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	index := int(s.calls.Add(1)) - 1
	if index >= len(s.steps) {
		return nil, errors.New("unexpected transport call")
	}
	return s.steps[index](req)
}

func (s *scriptedRoundTripper) CloseIdleConnections() {
	s.closeIdle.Add(1)
}

type trackingBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *trackingBody) Close() error {
	b.closed.Store(true)
	return nil
}

func newScriptedClient(rt http.RoundTripper, retries int) *retryablehttp.Client {
	options := retryablehttp.DefaultOptionsSingle
	options.HttpClient = &http.Client{Transport: rt}
	options.RetryMax = retries
	options.RetryWaitMin = 0
	options.RetryWaitMax = 0
	options.Timeout = 5 * time.Second
	return retryablehttp.NewClient(options)
}

func newDetectingClient(rt http.RoundTripper, retries int) *retryablehttp.Client {
	baselines := protocolstate.NewExpiringDurationMap(time.Minute)
	for _, host := range []string{
		"example.test", "redirected.example:8443", "origin.example", "redirect-target.example",
	} {
		baselines.StoreMin(host, 100*time.Millisecond, time.Minute)
	}
	client := newScriptedClient(&desyncDetectingTransport{
		base: rt, enabled: true, baselines: baselines,
	}, retries)
	client.CheckRetry = withoutDesyncRetry(client.CheckRetry)
	return client
}

func tracedResponse(req *http.Request, reused, beforeHeaders bool, protoMajor int, body io.ReadCloser) *http.Response {
	trace := httptrace.ContextClientTrace(req.Context())
	if trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{Reused: reused})
	}
	if beforeHeaders {
		if trace != nil && trace.GotFirstResponseByte != nil {
			trace.GotFirstResponseByte()
		}
		if trace != nil && trace.WroteHeaders != nil {
			trace.WroteHeaders()
		}
	} else {
		if trace != nil && trace.WroteHeaders != nil {
			trace.WroteHeaders()
		}
		if reused {
			time.Sleep(60 * time.Millisecond)
		}
		if trace != nil && trace.GotFirstResponseByte != nil {
			trace.GotFirstResponseByte()
		}
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		ProtoMajor: protoMajor,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       body,
		Request:    req,
	}
}

func TestDesyncRecoveryRetriesClosesAndQuarantines(t *testing.T) {
	badBody := &trackingBody{Reader: strings.NewReader("wrong")}
	firstRT := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			return tracedResponse(req, true, true, 1, badBody), nil
		},
	}}
	secondRT := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			return tracedResponse(req, false, false, 1, io.NopCloser(strings.NewReader("correct"))), nil
		},
	}}
	first := newDetectingClient(firstRT, 3)
	second := newScriptedClient(secondRT, 0)
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.test/", nil)
	require.NoError(t, err)
	hosts := protocolstate.NewExpiringSet(time.Minute)
	before := DesyncedResponses()

	resp, used, recovered, err := doWithDesyncRecovery(
		first, req, "example.test", hosts,
		func(string) (*retryablehttp.Client, error) { return second, nil },
	)
	require.NoError(t, err)
	require.True(t, recovered)
	require.Same(t, second, used)
	require.True(t, badBody.closed.Load(), "the misattributed response body must be closed")
	require.Equal(t, int64(1), firstRT.calls.Load(), "retryablehttp must not retry on the poisoned transport")
	require.Equal(t, int64(1), firstRT.closeIdle.Load(), "the poisoned idle pool must be closed")
	require.True(t, hosts.Contains("example.test"))
	require.Equal(t, before+1, DesyncedResponses())

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "correct", string(data))
	require.NoError(t, resp.Body.Close())
}

func TestDesyncRecoveryAttributesFinalRedirectHost(t *testing.T) {
	firstRT := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			return tracedResponse(req, true, true, 1, io.NopCloser(strings.NewReader("wrong"))), nil
		},
	}}
	secondRT := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			return tracedResponse(req, false, false, 1, io.NopCloser(strings.NewReader("correct"))), nil
		},
	}}
	first := newDetectingClient(firstRT, 0)
	second := newScriptedClient(secondRT, 0)
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://redirected.example:8443/", nil)
	require.NoError(t, err)
	hosts := protocolstate.NewExpiringSet(time.Minute)
	var factoryHost string

	resp, _, recovered, err := doWithDesyncRecovery(
		first, req, "origin.example:80", hosts,
		func(host string) (*retryablehttp.Client, error) {
			factoryHost = host
			return second, nil
		},
	)
	require.NoError(t, err)
	require.True(t, recovered)
	require.Equal(t, "redirected.example:8443", factoryHost)
	require.True(t, hosts.Contains("redirected.example:8443"))
	require.False(t, hosts.Contains("origin.example:80"))
	require.NoError(t, resp.Body.Close())
}

func TestDesyncRecoveryStopsBeforeFollowingPoisonedRedirect(t *testing.T) {
	firstRT := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			resp := tracedResponse(req, true, true, 1, io.NopCloser(strings.NewReader("redirect")))
			resp.StatusCode = http.StatusFound
			resp.Header.Set("Location", "http://redirect-target.example/")
			return resp, nil
		},
	}}
	secondRT := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			return tracedResponse(req, false, false, 1, io.NopCloser(strings.NewReader("correct"))), nil
		},
	}}
	first := newDetectingClient(firstRT, 3)
	second := newScriptedClient(secondRT, 0)
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://origin.example/", nil)
	require.NoError(t, err)

	resp, _, detected, err := doWithDesyncRecovery(
		first, req, "origin.example", protocolstate.NewExpiringSet(time.Minute),
		func(string) (*retryablehttp.Client, error) { return second, nil },
	)
	require.NoError(t, err)
	require.True(t, detected)
	require.Equal(t, int64(1), firstRT.calls.Load(),
		"the poisoned redirect must not be followed or retried on its transport")
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "correct", string(data))
	require.NoError(t, resp.Body.Close())
}

func TestDesyncRecoveryAllowsHealthyFastHTTP1Response(t *testing.T) {
	rt := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			return tracedResponse(req, true, false, 1, io.NopCloser(strings.NewReader("ok"))), nil
		},
	}}
	client := newDetectingClient(rt, 0)
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.test/", nil)
	require.NoError(t, err)
	factoryCalled := false

	resp, used, recovered, err := doWithDesyncRecovery(
		client, req, "example.test:443", protocolstate.NewExpiringSet(time.Minute),
		func(string) (*retryablehttp.Client, error) {
			factoryCalled = true
			return nil, nil
		},
	)
	require.NoError(t, err)
	require.False(t, recovered)
	require.False(t, factoryCalled)
	require.Same(t, client, used)
	require.NoError(t, resp.Body.Close())
}

func TestDesyncRecoveryIgnoresHTTP2(t *testing.T) {
	rt := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			return tracedResponse(req, true, true, 2, io.NopCloser(strings.NewReader("h2"))), nil
		},
	}}
	client := newDetectingClient(rt, 0)
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.test/", nil)
	require.NoError(t, err)

	resp, _, recovered, err := doWithDesyncRecovery(
		client, req, "example.test:443", protocolstate.NewExpiringSet(time.Minute),
		func(string) (*retryablehttp.Client, error) {
			t.Fatal("HTTP/2 must not be quarantined")
			return nil, nil
		},
	)
	require.NoError(t, err)
	require.False(t, recovered)
	require.NoError(t, resp.Body.Close())
}

func TestDesyncRecoveryIgnoresFreshConnection(t *testing.T) {
	rt := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			return tracedResponse(req, false, true, 1, io.NopCloser(strings.NewReader("ok"))), nil
		},
	}}
	client := newDetectingClient(rt, 0)
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.test/", nil)
	require.NoError(t, err)

	resp, _, recovered, err := doWithDesyncRecovery(
		client, req, "example.test:80", protocolstate.NewExpiringSet(time.Minute),
		func(string) (*retryablehttp.Client, error) {
			t.Fatal("fresh connection must not be retried")
			return nil, nil
		},
	)
	require.NoError(t, err)
	require.False(t, recovered)
	require.NoError(t, resp.Body.Close())
}

func TestDesyncRecoveryReplaysRequestBody(t *testing.T) {
	const payload = "important-post-body"
	var bodies []string
	makeStep := func(reused, before bool) func(*http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			data, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			bodies = append(bodies, string(data))
			return tracedResponse(req, reused, before, 1, io.NopCloser(strings.NewReader("ok"))), nil
		}
	}
	first := newDetectingClient(&scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		makeStep(true, true),
	}}, 0)
	second := newScriptedClient(&scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		makeStep(false, false),
	}}, 0)
	req, err := retryablehttp.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Idempotency-Key", "scan-request-1")

	resp, _, recovered, err := doWithDesyncRecovery(
		first, req, "example.test:80", protocolstate.NewExpiringSet(time.Minute),
		func(string) (*retryablehttp.Client, error) { return second, nil },
	)
	require.NoError(t, err)
	require.True(t, recovered)
	require.Equal(t, []string{payload, payload}, bodies)
	require.NoError(t, resp.Body.Close())
}

func TestDesyncRecoveryRejectsUnreplayableBody(t *testing.T) {
	first := newDetectingClient(&scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			_, _ = io.Copy(io.Discard, req.Body)
			return tracedResponse(req, true, true, 1, io.NopCloser(strings.NewReader("wrong"))), nil
		},
	}}, 0)
	req, err := retryablehttp.NewRequest(http.MethodPut, "http://example.test/", nil)
	require.NoError(t, err)
	req.Body = io.NopCloser(strings.NewReader("stream"))
	req.GetBody = nil

	resp, _, recovered, err := doWithDesyncRecovery(
		first, req, "example.test:80", protocolstate.NewExpiringSet(time.Minute),
		func(string) (*retryablehttp.Client, error) {
			t.Fatal("unreplayable body must not be retried")
			return nil, nil
		},
	)
	require.Nil(t, resp)
	require.True(t, recovered)
	require.ErrorContains(t, err, "not replayable")
	require.ErrorIs(t, err, ErrDesyncedResponse)
}

func TestDesyncRecoveryRefusesNonIdempotentReplay(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodConnect} {
		t.Run(method, func(t *testing.T) {
			badBody := &trackingBody{Reader: strings.NewReader("wrong")}
			first := newDetectingClient(&scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
				func(req *http.Request) (*http.Response, error) {
					return tracedResponse(req, true, true, 1, badBody), nil
				},
			}}, 0)
			req, err := retryablehttp.NewRequest(method, "http://example.test/", nil)
			require.NoError(t, err)
			hosts := protocolstate.NewExpiringSet(time.Minute)

			resp, used, detected, err := doWithDesyncRecovery(
				first, req, "example.test", hosts,
				func(string) (*retryablehttp.Client, error) {
					t.Fatal("non-idempotent request must not be replayed")
					return nil, nil
				},
			)
			require.Nil(t, resp)
			require.Same(t, first, used)
			require.True(t, detected)
			require.ErrorIs(t, err, ErrDesyncedResponse)
			require.ErrorContains(t, err, "refusing to replay")
			require.True(t, badBody.closed.Load())
			require.True(t, hosts.Contains("example.test"))
		})
	}
}

func TestRequestReplaySafePolicy(t *testing.T) {
	for _, method := range []string{
		http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace,
		http.MethodPut, http.MethodDelete,
	} {
		require.True(t, requestReplaySafe(&http.Request{Method: method, Header: make(http.Header)}), method)
	}
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodConnect} {
		require.False(t, requestReplaySafe(&http.Request{Method: method, Header: make(http.Header)}), method)
		require.True(t, requestReplaySafe(&http.Request{
			Method: method,
			Header: http.Header{"Idempotency-Key": []string{"key"}},
		}), method)
	}
	require.False(t, requestReplaySafe(nil))
}

func TestDesyncRecoveryPreservesCookieJar(t *testing.T) {
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	origin, err := url.Parse("http://example.test/")
	require.NoError(t, err)
	jar.SetCookies(origin, []*http.Cookie{{Name: "sess", Value: "valid-token"}})

	firstRT := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			return tracedResponse(req, true, true, 1, io.NopCloser(strings.NewReader("wrong"))), nil
		},
	}}
	secondRT := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			cookie, cookieErr := req.Cookie("sess")
			require.NoError(t, cookieErr)
			require.Equal(t, "valid-token", cookie.Value)
			return tracedResponse(req, false, false, 1, io.NopCloser(strings.NewReader("welcome-admin"))), nil
		},
	}}
	first := newDetectingClient(firstRT, 0)
	first.HTTPClient.Jar = jar
	second := newScriptedClient(secondRT, 0)
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.test/profile", nil)
	require.NoError(t, err)

	resp, used, recovered, err := doWithDesyncRecovery(
		first, req, "example.test", protocolstate.NewExpiringSet(time.Minute),
		func(string) (*retryablehttp.Client, error) { return second, nil },
	)
	require.NoError(t, err)
	require.True(t, recovered)
	require.Same(t, second, used)
	require.Same(t, jar, used.HTTPClient.Jar)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "welcome-admin", string(body))
	require.NoError(t, resp.Body.Close())
}

func TestDesyncRecoveryPropagatesNoReuseClientFailure(t *testing.T) {
	firstRT := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			return tracedResponse(req, true, true, 1, io.NopCloser(strings.NewReader("wrong"))), nil
		},
	}}
	first := newDetectingClient(firstRT, 0)
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.test/", nil)
	require.NoError(t, err)

	resp, used, recovered, err := doWithDesyncRecovery(
		first, req, "example.test:80", protocolstate.NewExpiringSet(time.Minute),
		func(string) (*retryablehttp.Client, error) { return nil, errors.New("pool failed") },
	)
	require.Nil(t, resp)
	require.Same(t, first, used)
	require.True(t, recovered)
	require.ErrorContains(t, err, "pool failed")
	require.ErrorIs(t, err, ErrDesyncedResponse)
	require.Equal(t, int64(1), firstRT.calls.Load())
}

func TestDesyncProbeUsesFinalInternalRetryAttempt(t *testing.T) {
	rt := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			trace := httptrace.ContextClientTrace(req.Context())
			trace.GotConn(httptrace.GotConnInfo{Reused: true})
			trace.GotFirstResponseByte()
			return nil, errors.New("temporary")
		},
		func(req *http.Request) (*http.Response, error) {
			return tracedResponse(req, true, false, 1, io.NopCloser(strings.NewReader("ok"))), nil
		},
	}}
	client := newDetectingClient(rt, 1)
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.test/", nil)
	require.NoError(t, err)

	resp, _, recovered, err := doWithDesyncRecovery(
		client, req, "example.test:80", protocolstate.NewExpiringSet(time.Minute),
		func(string) (*retryablehttp.Client, error) {
			t.Fatal("successful final attempt must win")
			return nil, nil
		},
	)
	require.NoError(t, err)
	require.False(t, recovered)
	require.Equal(t, int64(2), rt.calls.Load())
	require.NoError(t, resp.Body.Close())
}

func TestDesyncRecoveryAllowsClientWithoutDetector(t *testing.T) {
	rt := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			require.Nil(t, httptrace.ContextClientTrace(req.Context()))
			return &http.Response{
				StatusCode: http.StatusOK,
				ProtoMajor: 1,
				Body:       io.NopCloser(strings.NewReader("ok")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		},
	}}
	client := newScriptedClient(rt, 0)
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.test/", nil)
	require.NoError(t, err)

	resp, _, recovered, err := doWithDesyncRecovery(
		client, req, "example.test:80", protocolstate.NewExpiringSet(time.Minute),
		func(string) (*retryablehttp.Client, error) { t.Fatal("disabled probe must not retry"); return nil, nil },
	)
	require.NoError(t, err)
	require.False(t, recovered)
	require.NoError(t, resp.Body.Close())
}

func TestDoWithDesyncRecoverySkipsExplicitNoKeepAlive(t *testing.T) {
	opts := newTestOptions(t, "test-desync-disabled-keepalive")
	cfg := &Configuration{Connection: &ConnectionConfiguration{DisableKeepAlive: true}}
	rt := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			require.Nil(t, httptrace.ContextClientTrace(req.Context()))
			return &http.Response{
				StatusCode: http.StatusOK,
				ProtoMajor: 1,
				Body:       io.NopCloser(strings.NewReader("ok")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		},
	}}
	client := newScriptedClient(rt, 0)
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.test/", nil)
	require.NoError(t, err)

	resp, used, recovered, err := DoWithDesyncRecovery(client, req, opts, cfg, "example.test")
	require.NoError(t, err)
	require.False(t, recovered)
	require.Same(t, client, used)
	require.NoError(t, resp.Body.Close())
}

func TestDoWithDesyncRecoverySkipsQuarantinedHost(t *testing.T) {
	opts := newTestOptions(t, "test-desync-already-quarantined")
	cfg := &Configuration{}
	MarkHostDesynced(opts, "example.test")
	rt := &scriptedRoundTripper{steps: []func(*http.Request) (*http.Response, error){
		func(req *http.Request) (*http.Response, error) {
			require.Nil(t, httptrace.ContextClientTrace(req.Context()))
			return &http.Response{
				StatusCode: http.StatusOK,
				ProtoMajor: 1,
				Body:       io.NopCloser(strings.NewReader("ok")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		},
	}}
	client := newScriptedClient(rt, 0)
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://example.test/", nil)
	require.NoError(t, err)

	resp, used, recovered, err := DoWithDesyncRecovery(client, req, opts, cfg, "example.test")
	require.NoError(t, err)
	require.False(t, recovered)
	require.Same(t, client, used)
	require.NoError(t, resp.Body.Close())
}
