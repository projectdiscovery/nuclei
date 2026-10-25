package httpbody

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestBodyRewindsAfterEOF(t *testing.T) {
	body := New([]byte("hello"))

	for range 2 {
		data, err := io.ReadAll(body)
		require.NoError(t, err)
		require.Equal(t, "hello", string(data))
	}
	require.Equal(t, 5, body.Len())
}

func TestSetGetBodyReturnsIndependentReaders(t *testing.T) {
	data := bytes.Repeat([]byte("abcdefgh"), 64*1024)
	req, err := retryablehttp.NewRequest(http.MethodPost, "http://example.com", nil)
	require.NoError(t, err)
	Set(req, data)
	require.Equal(t, int64(len(data)), req.ContentLength)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, err := req.GetBody()
			require.NoError(t, err)
			got, err := io.ReadAll(body)
			require.NoError(t, err)
			require.Equal(t, data, got)
		}()
	}
	wg.Wait()

	view, err := View(req)
	require.NoError(t, err)
	require.Equal(t, &data[0], &view[0], "view must not copy the body")
}

func TestViewReadsForeignBody(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodPost, "http://example.com", "foreign")
	require.NoError(t, err)

	view, err := View(req)
	require.NoError(t, err)
	require.Equal(t, "foreign", string(view))

	sent, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, "foreign", string(sent), "view must leave the body readable")
}

func TestRetryResendsFullBody(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 256*1024)
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		require.Equal(t, len(data), len(got))
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	opts := retryablehttp.DefaultOptionsSingle
	opts.RetryMax = 2
	opts.RetryWaitMin = 0
	opts.RetryWaitMax = 0
	opts.CheckRetry = func(_ context.Context, resp *http.Response, err error) (bool, error) {
		return err != nil || resp.StatusCode == http.StatusServiceUnavailable, nil
	}
	client := retryablehttp.NewClient(opts)

	req, err := retryablehttp.NewRequestWithContext(context.Background(), http.MethodPost, server.URL, nil)
	require.NoError(t, err)
	Set(req, data)

	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(2), attempts.Load())
}

func TestRedirectResendsBody(t *testing.T) {
	data := []byte("redirected body")
	var received []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		http.Redirect(w, r, "/end", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	req, err := retryablehttp.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/start", nil)
	require.NoError(t, err)
	Set(req, data)

	resp, err := http.DefaultClient.Do(req.Request)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, data, received)
}

func TestSetDoesNotCopyLargeBody(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 8*1024*1024)
	req, err := retryablehttp.NewRequest(http.MethodPost, "http://example.com", nil)
	require.NoError(t, err)
	buf := make([]byte, 32*1024)

	allocs := testing.AllocsPerRun(5, func() {
		Set(req, data)
		body, _ := req.GetBody()
		for {
			if _, err := body.Read(buf); err != nil {
				break
			}
		}
	})
	require.LessOrEqual(t, allocs, float64(8), "reading the body must not allocate per read")
}
