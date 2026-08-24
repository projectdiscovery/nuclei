package httpclientpool

import (
	"net/http/httptrace"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/stretchr/testify/require"
)

func newProbeWithBaseline(host string, baseline time.Duration) *DesyncProbe {
	baselines := protocolstate.NewExpiringDurationMap(time.Minute)
	baselines.StoreMin(host, baseline, time.Minute)
	return NewDesyncProbe(host, baselines)
}

func TestDesyncProbeFlagsImplausiblyFastReusedResponse(t *testing.T) {
	t.Parallel()

	probe := newProbeWithBaseline("example.com", 100*time.Millisecond)
	now := time.Now()
	probe.reused = true
	probe.gotConn = now
	probe.wroteHeaders = now
	probe.firstByte = now.Add(time.Millisecond)

	require.True(t, probe.Suspect())
}

func TestDesyncProbeAllowsGenuineResponse(t *testing.T) {
	t.Parallel()

	probe := newProbeWithBaseline("example.com", 100*time.Millisecond)
	now := time.Now()
	probe.reused = true
	probe.gotConn = now
	probe.wroteHeaders = now
	probe.firstByte = now.Add(60 * time.Millisecond)

	require.False(t, probe.Suspect())
}

func TestDesyncProbeUsesConnectionCheckoutBeforeWroteHeaders(t *testing.T) {
	t.Parallel()

	probe := newProbeWithBaseline("example.com", 100*time.Millisecond)
	now := time.Now()
	probe.reused = true
	probe.gotConn = now
	probe.firstByte = now.Add(time.Millisecond)
	probe.wroteHeaders = now.Add(2 * time.Millisecond)

	require.True(t, probe.Suspect())
}

func TestDesyncProbeAllowsLargeHeaderEarlyResponse(t *testing.T) {
	t.Parallel()

	probe := newProbeWithBaseline("example.com", 100*time.Millisecond)
	now := time.Now()
	probe.reused = true
	probe.gotConn = now
	probe.firstByte = now.Add(60 * time.Millisecond)
	probe.wroteHeaders = now.Add(70 * time.Millisecond)

	require.False(t, probe.Suspect())
}

func TestDesyncProbeIgnoresFreshConnection(t *testing.T) {
	t.Parallel()

	probe := newProbeWithBaseline("example.com", 100*time.Millisecond)
	now := time.Now()
	probe.gotConn = now
	probe.wroteHeaders = now
	probe.firstByte = now.Add(time.Millisecond)

	require.False(t, probe.Suspect())
}

func TestDesyncProbeRequiresBaseline(t *testing.T) {
	t.Parallel()

	probe := NewDesyncProbe("example.com", protocolstate.NewExpiringDurationMap(time.Minute))
	now := time.Now()
	probe.reused = true
	probe.gotConn = now
	probe.wroteHeaders = now
	probe.firstByte = now.Add(time.Millisecond)
	require.False(t, probe.Suspect())
}

func TestDesyncProbeConcurrentCallbacksAreRaceSafe(t *testing.T) {
	t.Parallel()

	for range 100 {
		probe := newProbeWithBaseline("example.com", 100*time.Millisecond)
		trace := probe.Trace()
		trace.GotConn(httptrace.GotConnInfo{Reused: true})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			trace.WroteHeaders()
		}()
		go func() {
			defer wg.Done()
			trace.GotFirstResponseByte()
		}()
		wg.Wait()
		_ = probe.Suspect()
	}
}

func BenchmarkDesyncProbeHealthyRequest(b *testing.B) {
	baselines := protocolstate.NewExpiringDurationMap(time.Minute)
	baselines.StoreMin("example.com", time.Millisecond, time.Minute)
	b.ReportAllocs()
	for range b.N {
		probe := NewDesyncProbe("example.com", baselines)
		now := time.Now()
		probe.reused = true
		probe.gotConn = now
		probe.wroteHeaders = now
		probe.firstByte = now.Add(time.Millisecond)
		if probe.Suspect() {
			b.Fatal("healthy ordering reported as desynchronized")
		}
	}
}
