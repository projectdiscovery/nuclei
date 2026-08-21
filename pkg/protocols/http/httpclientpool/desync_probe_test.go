package httpclientpool

import (
	"net/http/httptrace"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// roundTrip is the handshake the probe learns as the host's network floor. Real and
// generous: the signal it separates is microseconds against milliseconds.
const roundTrip = 20 * time.Millisecond

func TestDesyncProbeFlagsResponseThatBeatTheNetwork(t *testing.T) {
	t.Parallel()

	const host = "prebuffered.example.test:443"
	learnRoundTrip(t, host)

	probe := NewDesyncProbe(host)
	trace := probe.Trace()
	trace.GotConn(httptrace.GotConnInfo{Reused: true})
	trace.WroteHeaders()
	trace.GotFirstResponseByte() // already in the buffer: no round trip

	require.True(t, probe.Suspect(),
		"a response that arrived without a round trip belonged to an earlier request")
}

func TestDesyncProbeAllowsGenuineResponse(t *testing.T) {
	t.Parallel()

	const host = "healthy.example.test:443"
	learnRoundTrip(t, host)

	probe := NewDesyncProbe(host)
	trace := probe.Trace()
	trace.GotConn(httptrace.GotConnInfo{Reused: true})
	trace.WroteHeaders()
	time.Sleep(roundTrip)
	trace.GotFirstResponseByte()

	require.False(t, probe.Suspect(), "a response that waited for the network is this request's")
}

// A server may answer a large body early, before the request finishes being written,
// so the probe anchors on the headers rather than on the whole request.
func TestDesyncProbeAllowsEarlyAnswerToRequestBody(t *testing.T) {
	t.Parallel()

	const host = "earlybody.example.test:443"
	learnRoundTrip(t, host)

	probe := NewDesyncProbe(host)
	trace := probe.Trace()
	trace.GotConn(httptrace.GotConnInfo{Reused: true})
	trace.WroteHeaders()
	time.Sleep(roundTrip) // server answers while the body is still uploading
	trace.GotFirstResponseByte()

	require.False(t, probe.Suspect())
}

func TestDesyncProbeIgnoresFreshConnection(t *testing.T) {
	t.Parallel()

	const host = "fresh.example.test:443"

	probe := NewDesyncProbe(host)
	trace := probe.Trace()
	trace.ConnectStart("tcp", host)
	time.Sleep(roundTrip)
	trace.ConnectDone("tcp", host, nil)
	trace.GotConn(httptrace.GotConnInfo{Reused: false})
	trace.WroteHeaders()
	trace.GotFirstResponseByte()

	require.False(t, probe.Suspect(),
		"the first response on a connection cannot be someone else's")

	rtt, ok := hostRTTFor(host)
	require.True(t, ok, "a fresh connection must contribute its handshake")
	require.GreaterOrEqual(t, rtt, roundTrip)
	t.Cleanup(func() { hostRTT.Delete(desyncedHostKey(host)) })
}

func TestDesyncProbeWithoutBaselineDoesNotGuess(t *testing.T) {
	t.Parallel()

	const host = "unmeasured.example.test:443"

	probe := NewDesyncProbe(host)
	trace := probe.Trace()
	trace.GotConn(httptrace.GotConnInfo{Reused: true})
	trace.WroteHeaders()
	trace.GotFirstResponseByte()

	require.False(t, probe.Suspect(),
		"with no measured round trip, flagging would cost a healthy host its reuse")
}

func TestDesyncProbeFlagsResponseBeforeHeaders(t *testing.T) {
	t.Parallel()

	const host = "beforeheaders.example.test:443"
	learnRoundTrip(t, host)

	probe := NewDesyncProbe(host)
	trace := probe.Trace()
	trace.GotConn(httptrace.GotConnInfo{Reused: true})
	trace.GotFirstResponseByte() // the read loop won the race against the write loop

	require.True(t, probe.Suspect())
}

// learnRoundTrip gives the host a handshake measurement, the way a fresh connection
// would, so later requests have a floor to be judged against.
func learnRoundTrip(t *testing.T, host string) {
	t.Helper()

	probe := NewDesyncProbe(host)
	trace := probe.Trace()
	trace.ConnectStart("tcp", host)
	time.Sleep(roundTrip)
	trace.ConnectDone("tcp", host, nil)
	trace.GotConn(httptrace.GotConnInfo{Reused: false})

	require.False(t, probe.Suspect())
	t.Cleanup(func() { hostRTT.Delete(desyncedHostKey(host)) })
}
