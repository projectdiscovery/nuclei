package http

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
)

type replayTransport func(*http.Request) (*http.Response, error)

func (transport replayTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestReplayableStringBodyPreservesRequest(t *testing.T) {
	for _, tc := range []struct {
		name, method, body, transferEncoding string
		contentLength                        int64
	}{
		{name: "post", method: http.MethodPost, body: "body", contentLength: 1},
		{name: "get", method: http.MethodGet, body: "body", contentLength: 3},
		{name: "head", method: http.MethodHead, body: "body", contentLength: 0},
		{name: "chunked", method: http.MethodPost, body: "body", transferEncoding: "chunked", contentLength: -1},
		{name: "empty", method: http.MethodPost, body: "", contentLength: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			legacy, err := retryablehttp.NewRequest(tc.method, "https://example.test/", tc.body)
			if err != nil {
				t.Fatal(err)
			}
			current, err := retryablehttp.NewRequest(tc.method, "https://example.test/", nil)
			if err != nil {
				t.Fatal(err)
			}
			setReplayableStringBody(current, tc.body)
			legacy.ContentLength = tc.contentLength
			current.ContentLength = tc.contentLength
			if tc.transferEncoding != "" {
				legacy.Header.Set("Transfer-Encoding", tc.transferEncoding)
				current.Header.Set("Transfer-Encoding", tc.transferEncoding)
			}
			for _, request := range []*retryablehttp.Request{legacy, current} {
				if err := reuseRequestBody(request); err != nil {
					t.Fatal(err)
				}
			}
			if legacy.ContentLength != current.ContentLength {
				t.Fatalf("content length changed: legacy=%d replay=%d", legacy.ContentLength, current.ContentLength)
			}
			for _, request := range []*retryablehttp.Request{legacy, current} {
				got, err := io.ReadAll(request.Body)
				if err != nil || string(got) != tc.body {
					t.Fatalf("request body mismatch: %q, %v", got, err)
				}
				for i := 0; i < 2; i++ {
					fresh, err := request.GetBody()
					if err != nil {
						t.Fatal(err)
					}
					got, err = io.ReadAll(fresh)
					if err != nil || string(got) != tc.body {
						t.Fatalf("replay %d mismatch: %q, %v", i, got, err)
					}
				}
			}
			legacyDump, legacyErr := dump(&generatedRequest{request: legacy}, "https://example.test/")
			currentDump, currentErr := dump(&generatedRequest{request: current}, "https://example.test/")
			if legacyErr != nil || currentErr != nil || !bytes.Equal(legacyDump, currentDump) {
				t.Fatalf("request dump mismatch: legacy=%v replay=%v", legacyErr, currentErr)
			}
		})
	}
}

func TestReplayableStringBodyConcurrentDump(t *testing.T) {
	value := strings.Repeat("probe", 1<<20)
	request, err := retryablehttp.NewRequest(http.MethodPost, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	setReplayableStringBody(request, value)
	if err := reuseRequestBody(request); err != nil {
		t.Fatal(err)
	}
	generated := &generatedRequest{request: request}

	var group sync.WaitGroup
	errors := make(chan error, 4)
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			got, err := dump(generated, "https://example.test/")
			if err == nil && !bytes.HasSuffix(got, []byte(value)) {
				err = io.ErrUnexpectedEOF
			}
			errors <- err
		}()
	}
	got, err := io.ReadAll(request.Body)
	if err != nil || string(got) != value {
		t.Fatalf("transport body mismatch: %v", err)
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestReplayableStringBodyRetryAndRedirect(t *testing.T) {
	value := strings.Repeat("probe", 1<<18)
	for _, tc := range []struct {
		name             string
		firstStatus      int
		redirectLocation string
	}{
		{name: "retry", firstStatus: http.StatusServiceUnavailable},
		{name: "redirect", firstStatus: http.StatusTemporaryRedirect, redirectLocation: "/final"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var received int
			transport := replayTransport(func(request *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(request.Body)
				if err != nil || string(body) != value {
					t.Errorf("delivery %d body mismatch: %v", received, err)
				}
				received++
				status := http.StatusOK
				headers := make(http.Header)
				if received == 1 {
					status = tc.firstStatus
					if tc.redirectLocation != "" {
						headers.Set("Location", tc.redirectLocation)
					}
				}
				return &http.Response{
					StatusCode: status,
					Header:     headers,
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    request,
				}, nil
			})
			request, err := retryablehttp.NewRequest(http.MethodPost, "http://example.test/start", nil)
			if err != nil {
				t.Fatal(err)
			}
			setReplayableStringBody(request, value)
			if err := reuseRequestBody(request); err != nil {
				t.Fatal(err)
			}
			client := retryablehttp.NewClient(retryablehttp.Options{
				HttpClient:   &http.Client{Transport: transport, Timeout: time.Second},
				RetryMax:     1,
				RetryWaitMin: time.Nanosecond,
				RetryWaitMax: time.Nanosecond,
				CheckRetry: func(_ context.Context, response *http.Response, err error) (bool, error) {
					return err == nil && response.StatusCode == http.StatusServiceUnavailable, err
				},
			})
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := response.Body.Close(); err != nil {
					t.Errorf("close replay response: %v", err)
				}
			})
			if response.StatusCode != http.StatusOK || received != 2 {
				t.Fatalf("got status %d and %d deliveries", response.StatusCode, received)
			}
		})
	}
}
