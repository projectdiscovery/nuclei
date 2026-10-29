package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/httpbody"
)

// The budget fits one 1MB body, so three concurrent requests run one at a
// time. The third waits about 2.4s to be admitted, longer than the 3s HTTP
// timeout leaves once its own 1.2s send is added, so it only matches if the
// timeout starts after admission.
func TestRequestBodyBudgetQueuesHeavyRequests(t *testing.T) {
	const bodySize = 1 << 20
	const requests = 3

	var inFlight, maxInFlight atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			seen := maxInFlight.Load()
			if n <= seen || maxInFlight.CompareAndSwap(seen, n) {
				break
			}
		}
		body, _ := io.ReadAll(r.Body)
		time.Sleep(1200 * time.Millisecond)
		if len(body) == bodySize {
			_, _ = io.WriteString(w, "full body")
		}
	}))
	defer ts.Close()

	options := testutils.DefaultOptions.Copy()
	options.SetTimeouts(&types.Timeouts{DialTimeout: time.Second, HttpTimeout: 3 * time.Second})
	testutils.Init(options)

	request := &Request{
		ID:     "body-budget",
		Path:   []string{"{{BaseURL}}"},
		Method: HTTPMethodTypeHolder{MethodType: HTTPPost},
		Body:   `{{repeat("A", 1048576)}}`,
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Part:  "body",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"full body"},
			}},
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOpts.RequestBodyBudget = httpbody.NewBudget(bodySize)
	require.NoError(t, request.Compile(executerOpts))

	var matched atomic.Int32
	var wg sync.WaitGroup
	for range requests {
		wg.Go(func() {
			err := request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), ts.URL), make(output.InternalEvent), make(output.InternalEvent), func(event *output.InternalWrappedEvent) {
				if event.OperatorsResult != nil && event.OperatorsResult.Matched {
					matched.Add(1)
				}
			})
			require.NoError(t, err)
		})
	}
	wg.Wait()

	require.EqualValues(t, 1, maxInFlight.Load(), "budget must hold heavy requests to one in flight")
	require.EqualValues(t, requests, matched.Load(), "queued requests must not time out while waiting")
}

func TestReserveBodyQueuesBuildsOnLearnedSize(t *testing.T) {
	const bodySize = 4 << 20
	request := &Request{
		options:  &protocols.ExecutorOptions{RequestBodyBudget: httpbody.NewBudget(6 << 20)},
		bodySize: &bodySizeEstimate{},
	}

	// Until a size is known, the first build runs alone.
	first, err := request.reserveBody(t.Context())
	require.NoError(t, err)
	blocked := make(chan struct{})
	go func() {
		second, err := request.reserveBody(t.Context())
		require.NoError(t, err)
		second.done()
		close(blocked)
	}()
	select {
	case <-blocked:
		t.Fatal("second build started before the first recorded its size")
	case <-time.After(20 * time.Millisecond):
	}
	require.NoError(t, first.built(t.Context(), request, bodySize))
	first.done()
	<-blocked

	// Once known, each build reserves that size before it starts.
	held, err := request.reserveBody(t.Context())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err = request.reserveBody(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	held.done()
	next, err := request.reserveBody(t.Context())
	require.NoError(t, err)
	next.done()
}

func TestReserveBodyGrowsToLargerBody(t *testing.T) {
	request := &Request{
		options:  &protocols.ExecutorOptions{RequestBodyBudget: httpbody.NewBudget(6 << 20)},
		bodySize: &bodySizeEstimate{},
	}
	learn, err := request.reserveBody(t.Context())
	require.NoError(t, err)
	require.NoError(t, learn.built(t.Context(), request, 1<<20))
	learn.done()

	grown, err := request.reserveBody(t.Context())
	require.NoError(t, err)
	require.NoError(t, grown.built(t.Context(), request, 5<<20))

	// 5MB of 6MB is held, so another 5MB build has to wait.
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err = request.reserveBody(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	grown.done()
}
