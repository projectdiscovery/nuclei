package http

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/retryablehttp-go"
)

func TestReplayBodyExactBytesAndIndependentReaders(t *testing.T) {
	part := "--\nContent-Disposition:name=a[]" + strings.Repeat("[a]", 62) + ";filename=\n\n"
	for _, probe := range []struct{ sizeMiB, parts int }{{1, 4000}, {8, 1020}, {20, 1020}} {
		size := probe.sizeMiB * 1048576
		fillerCount := (size - len(part)*probe.parts) / 3
		want := "--\n" + strings.Repeat("x:\n", fillerCount) + strings.Repeat(part, probe.parts)[3:]
		want = want[:len(want)-1]
		body, err := NewReplayBody([]ReplayPart{
			{Pattern: "--\n", Count: 1},
			{Pattern: "x:\n", Count: int64(fillerCount)},
			{Pattern: part[3:], Count: 1},
			{Pattern: part, Count: int64(probe.parts - 1)},
		}, 1)
		if err != nil {
			t.Fatal(err)
		}
		if body.Len() != int64(len(want)) {
			t.Fatalf("%d MiB: got length %d, want %d", probe.sizeMiB, body.Len(), len(want))
		}
		for replay := 0; replay < 3; replay++ {
			reader := body.NewReader()
			got, err := io.ReadAll(reader)
			if err != nil || string(got) != want {
				t.Fatalf("%d MiB replay %d differs: %v", probe.sizeMiB, replay, err)
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestReplayBodyRejectsInvalidLengths(t *testing.T) {
	for _, tc := range []struct {
		parts []ReplayPart
		trim  int64
	}{
		{parts: []ReplayPart{{Pattern: "x", Count: -1}}},
		{parts: []ReplayPart{{Pattern: "xx", Count: int64(^uint64(0) >> 1)}}},
		{parts: []ReplayPart{{Pattern: "x", Count: 1}}, trim: 2},
		{parts: []ReplayPart{{Pattern: "x", Count: 1}}, trim: -1},
	} {
		if _, err := NewReplayBody(tc.parts, tc.trim); err == nil {
			t.Fatalf("accepted invalid replay body: %+v", tc)
		}
	}
}

func TestReplayBodyRetryAndRedirect(t *testing.T) {
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
			source, err := NewReplayBody([]ReplayPart{{Pattern: "probe", Count: 1 << 18}}, 0)
			if err != nil {
				t.Fatal(err)
			}
			request, err := retryablehttp.NewRequest(http.MethodPost, "http://example.test/start", nil)
			if err != nil {
				t.Fatal(err)
			}
			setReplayBody(request, source)
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
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK || received != 2 {
				t.Fatalf("got status %d and %d deliveries", response.StatusCode, received)
			}
		})
	}
}

func TestReplayBodyRawAndStructuredRequests(t *testing.T) {
	for _, tc := range []struct {
		raw, selfContained bool
	}{
		{raw: false},
		{raw: true},
		{raw: true, selfContained: true},
	} {
		options := testutils.DefaultOptions
		testutils.Init(options)
		request := &Request{ID: "replay-body-test", Name: "replay-body-test", Method: HTTPMethodTypeHolder{MethodType: HTTPPost}, SelfContained: tc.selfContained}
		if tc.selfContained {
			request.Raw = []string{"POST http://127.0.0.1/probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n{{probe_body}}\r\n"}
		} else if tc.raw {
			request.Raw = []string{"POST /probe HTTP/1.1\r\nHost: {{Hostname}}\r\nX-Probe: yes\r\n\r\n{{probe_body}}\r\n"}
		} else {
			request.Path = []string{"{{BaseURL}}/probe"}
			request.Body = "{{probe_body}}"
		}
		executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
			ID: "replay-body-test", Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "replay-body-test"},
		})
		if err := request.Compile(executerOpts); err != nil {
			t.Fatal(err)
		}
		body, err := NewReplayBody([]ReplayPart{{Pattern: "abc", Count: 3}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		inputURL := "http://example.com"
		if tc.selfContained {
			inputURL = ""
		}
		input := contextargs.NewWithInput(context.Background(), inputURL)
		executerOpts.GetTemplateCtx(input.MetaInput).Set("probe_body", body)
		generator := request.newGenerator(false)
		data, payloads, ok := generator.nextValue()
		if !ok {
			t.Fatal("request generator returned no request")
		}
		generated, err := generator.Make(context.Background(), input, data, payloads, map[string]interface{}{})
		if err != nil {
			t.Fatal(err)
		}
		if generated.request.Method != http.MethodPost || generated.request.ContentLength != body.Len() {
			t.Fatalf("raw=%v self-contained=%v: method=%s length=%d", tc.raw, tc.selfContained, generated.request.Method, generated.request.ContentLength)
		}
		if err := reuseRequestBody(generated.request); err != nil {
			t.Fatal(err)
		}
		for replay := 0; replay < 2; replay++ {
			reader, err := generated.request.GetBody()
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(reader)
			if err != nil || string(got) != "abcabcab" {
				t.Fatalf("raw=%v self-contained=%v replay=%d: %q %v", tc.raw, tc.selfContained, replay, got, err)
			}
		}
		dumped, err := dump(generated, input.MetaInput.Input)
		if err != nil || !bytes.HasSuffix(dumped, []byte("abcabcab")) {
			t.Fatalf("raw=%v self-contained=%v dump mismatch: %v", tc.raw, tc.selfContained, err)
		}
	}
}
