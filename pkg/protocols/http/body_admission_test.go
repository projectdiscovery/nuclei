package http

import (
	"context"
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
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestLargeBodyAdmissionUsesMemoryBudget(t *testing.T) {
	admission := newBodyAdmission(3 << 30)
	require.EqualValues(t, 48<<20, admission.limit)

	releases := make([]func(), 0, 2)
	for range 2 {
		release, err := admission.acquire(t.Context(), 20<<20)
		require.NoError(t, err)
		releases = append(releases, release)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err := admission.acquire(ctx, 20<<20)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	releases[0]()
	release, err := admission.acquire(t.Context(), 20<<20)
	require.NoError(t, err)
	release()
	releases[1]()
}

func TestSmallBodyBypassesLargeBodyAdmission(t *testing.T) {
	admission := newBodyAdmission(3 << 30)
	fullRelease, err := admission.acquire(t.Context(), admission.limit)
	require.NoError(t, err)
	defer fullRelease()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	release, err := admission.acquire(ctx, largeBodyThreshold-1)
	require.NoError(t, err)
	release()
}

func TestHTTPTimeoutStartsAfterLargeBodyAdmission(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = t.Name()
	options.SetTimeouts(&types.Timeouts{HttpTimeout: time.Second})
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	var sent atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		sent.Store(true)
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	request := &Request{
		ID:     "large-body-timeout",
		Path:   []string{"{{BaseURL}}"},
		Method: HTTPMethodTypeHolder{MethodType: HTTPPost},
		Body:   "{{probe_body}}",
	}
	executerOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: request.ID},
	})
	require.NoError(t, request.Compile(executerOptions))
	input := contextargs.NewWithInput(t.Context(), server.URL)
	body, err := NewReplayBody([]ReplayPart{{Pattern: "x", Count: 2 << 20}}, 0)
	require.NoError(t, err)
	executerOptions.GetTemplateCtx(input.MetaInput).Set("probe_body", body)

	sharedBodyAdmissionOnce.Do(func() { sharedBodyAdmission = systemBodyAdmission() })
	previousAdmission := sharedBodyAdmission
	sharedBodyAdmission = newBodyAdmission(64 << 20)
	t.Cleanup(func() { sharedBodyAdmission = previousAdmission })
	hold, err := sharedBodyAdmission.acquire(t.Context(), body.Len())
	require.NoError(t, err)
	release := sync.OnceFunc(hold)
	defer release()
	time.AfterFunc(1500*time.Millisecond, release)

	require.NoError(t, request.ExecuteWithResults(input, nil, nil, func(*output.InternalWrappedEvent) {}))
	require.True(t, sent.Load())
}
