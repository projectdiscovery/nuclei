package hostbackoff

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHealthyHostIsNotDelayed(t *testing.T) {
	g := New(Config{})
	for i := 0; i < 10; i++ {
		g.Observe("acme.test", http.StatusOK, 0, nil)
	}
	require.Zero(t, g.Delay("acme.test"), "a host that answers normally must not be slowed")
}

func TestTooManyRequestsBacksOff(t *testing.T) {
	g := New(Config{Step: 100 * time.Millisecond, Factor: 2, Max: time.Second})

	g.Observe("acme.test", http.StatusTooManyRequests, 0, nil)
	require.Equal(t, 100*time.Millisecond, g.Delay("acme.test"))

	g.Observe("acme.test", http.StatusTooManyRequests, 0, nil)
	require.Equal(t, 200*time.Millisecond, g.Delay("acme.test"), "a repeat complaint grows the delay")
}

func TestServiceUnavailableBacksOff(t *testing.T) {
	g := New(Config{Step: 100 * time.Millisecond})
	g.Observe("acme.test", http.StatusServiceUnavailable, 0, nil)
	require.Equal(t, 100*time.Millisecond, g.Delay("acme.test"))
}

func TestTransportErrorBacksOff(t *testing.T) {
	g := New(Config{Step: 100 * time.Millisecond})
	g.Observe("acme.test", 0, 0, errors.New("connection reset"))
	require.Equal(t, 100*time.Millisecond, g.Delay("acme.test"))
}

// A single 403 is ordinary: plenty of templates probe endpoints the scan is not
// authorised for. A run of them is the host refusing the scanner.
func TestForbiddenOnlyBacksOffAsAStreak(t *testing.T) {
	g := New(Config{Step: 100 * time.Millisecond, ForbiddenStreak: 3})

	g.Observe("acme.test", http.StatusForbidden, 0, nil)
	g.Observe("acme.test", http.StatusForbidden, 0, nil)
	require.Zero(t, g.Delay("acme.test"), "an occasional 403 is not a block")

	g.Observe("acme.test", http.StatusForbidden, 0, nil)
	require.Equal(t, 100*time.Millisecond, g.Delay("acme.test"), "a streak is")
}

func TestOkResetsTheForbiddenStreak(t *testing.T) {
	g := New(Config{Step: 100 * time.Millisecond, ForbiddenStreak: 3})
	g.Observe("acme.test", http.StatusForbidden, 0, nil)
	g.Observe("acme.test", http.StatusForbidden, 0, nil)
	g.Observe("acme.test", http.StatusOK, 0, nil)
	g.Observe("acme.test", http.StatusForbidden, 0, nil)
	require.Zero(t, g.Delay("acme.test"), "the streak must start again after a healthy response")
}

// The host's own figure is the only one that is not a guess, so it wins when it
// is longer than what the governor would have chosen.
func TestRetryAfterIsHonouredWhenLonger(t *testing.T) {
	g := New(Config{Step: 100 * time.Millisecond, Max: time.Minute})

	g.Observe("acme.test", http.StatusTooManyRequests, 5*time.Second, nil)
	require.Equal(t, 5*time.Second, g.Delay("acme.test"))

	// a shorter Retry-After does not undo a longer backoff already earned
	g.Observe("acme.test", http.StatusTooManyRequests, time.Millisecond, nil)
	require.Equal(t, 10*time.Second, g.Delay("acme.test"))
}

func TestDelayIsCapped(t *testing.T) {
	g := New(Config{Step: time.Second, Factor: 10, Max: 2 * time.Second})
	for i := 0; i < 5; i++ {
		g.Observe("acme.test", http.StatusTooManyRequests, time.Hour, nil)
	}
	require.Equal(t, 2*time.Second, g.Delay("acme.test"), "neither growth nor Retry-After may exceed the cap")
}

func TestHealthyResponsesDecayTheDelay(t *testing.T) {
	g := New(Config{Step: 100 * time.Millisecond, Factor: 2, Decay: 0.5})
	g.Observe("acme.test", http.StatusTooManyRequests, 0, nil)
	g.Observe("acme.test", http.StatusTooManyRequests, 0, nil)
	require.Equal(t, 200*time.Millisecond, g.Delay("acme.test"))

	g.Observe("acme.test", http.StatusOK, 0, nil)
	require.Equal(t, 100*time.Millisecond, g.Delay("acme.test"))

	// below the first step there is nothing useful left to wait for
	g.Observe("acme.test", http.StatusOK, 0, nil)
	require.Zero(t, g.Delay("acme.test"))
}

func TestHostsAreIndependent(t *testing.T) {
	g := New(Config{Step: 100 * time.Millisecond})
	g.Observe("blocked.test", http.StatusTooManyRequests, 0, nil)
	require.Equal(t, 100*time.Millisecond, g.Delay("blocked.test"))
	require.Zero(t, g.Delay("healthy.test"), "one host complaining must not slow another")
}

func TestWaitSleepsAndRespectsCancellation(t *testing.T) {
	g := New(Config{Step: 50 * time.Millisecond})

	start := time.Now()
	require.NoError(t, g.Wait(context.Background(), "quiet.test"))
	require.Less(t, time.Since(start), 10*time.Millisecond, "a healthy host is not waited on")

	g.Observe("slow.test", http.StatusTooManyRequests, 0, nil)
	start = time.Now()
	require.NoError(t, g.Wait(context.Background(), "slow.test"))
	require.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)

	// a cancelled scan must not be held up by a long backoff
	g.Observe("stuck.test", http.StatusTooManyRequests, time.Hour, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, g.Wait(ctx, "stuck.test"), context.Canceled)
}

func TestWaitSpacesConcurrentCallers(t *testing.T) {
	const step = 60 * time.Millisecond
	g := New(Config{Step: step, Max: time.Second})
	g.Observe("burst.test", http.StatusTooManyRequests, 0, nil)

	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			require.NoError(t, g.Wait(context.Background(), "burst.test"))
		}()
	}
	wg.Wait()
	require.GreaterOrEqual(t, time.Since(start), 2*step-10*time.Millisecond)
}

// waitHost is the host the cancellation tests wait on.
const waitHost = "acme.test"

// pacedGovernor returns a governor that has slowed waitHost to one start per
// step.
func pacedGovernor(step time.Duration) *Governor {
	var cfg Config

	cfg.Step, cfg.Max = step, step
	governor := New(cfg)
	governor.Observe(waitHost, http.StatusTooManyRequests, 0, nil)

	return governor
}

// waitingCtx tells a test when Wait has started waiting on it. Wait calls
// Done only after it has reserved its slot, so the slot is held from then on.
type waitingCtx struct {
	context.Context //nolint:containedctx // waitingCtx is itself a context wrapping another

	once    sync.Once
	waiting chan struct{}
}

func (c *waitingCtx) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })

	return c.Context.Done()
}

// waitResult is what a background Wait returned, and when.
type waitResult struct {
	err error
	at  time.Time
}

// startWait runs Wait on waitHost in the background and returns once it holds
// its slot, with the func that cancels the wait and the channel that gets its
// result.
func startWait(t *testing.T, governor *Governor) (context.CancelFunc, <-chan waitResult) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	waitCtx := &waitingCtx{Context: ctx, once: sync.Once{}, waiting: make(chan struct{})}
	result := make(chan waitResult, 1)

	go func() {
		err := governor.Wait(waitCtx, waitHost)
		result <- waitResult{err: err, at: time.Now()}
	}()

	select {
	case <-waitCtx.waiting:
	case got := <-result:
		t.Fatalf("Wait returned %v before holding a slot", got.err)
	}

	return cancel, result
}

// A wait that is cancelled never sends its request, so its slot must not push
// back the callers that come after it (#8163).
func TestWaitCancelledSlotsDoNotDelayLaterCallers(t *testing.T) {
	t.Parallel()

	const step = 200 * time.Millisecond

	governor := pacedGovernor(step)

	for range 3 {
		cancel, result := startWait(t, governor)
		cancel()
		require.ErrorIs(t, (<-result).err, context.Canceled)
	}

	// Three slots held on would put this caller 4 steps out.
	ctx, cancel := context.WithTimeout(t.Context(), 5*step/2)
	defer cancel()

	start := time.Now()

	require.NoError(t, governor.Wait(ctx, waitHost))
	require.GreaterOrEqual(t, time.Since(start), step, "the host is still paced")
}

// Cancelled waits give back their slots in whatever order they stop, while
// live callers keep theirs, including one queued behind a cancelled wait.
func TestWaitCancelledSlotsKeepLiveCallersInPlace(t *testing.T) {
	t.Parallel()

	const step = 200 * time.Millisecond

	governor := pacedGovernor(step)

	// The slots start 1 to 5 steps from now.
	start := time.Now()
	_, first := startWait(t, governor)
	cancelSecond, second := startWait(t, governor)
	_, third := startWait(t, governor)
	cancelFourth, fourth := startWait(t, governor)
	cancelFifth, fifth := startWait(t, governor)

	cancelSecond()
	cancelFifth()
	cancelFourth()

	for _, result := range []<-chan waitResult{second, fourth, fifth} {
		require.ErrorIs(t, (<-result).err, context.Canceled)
	}

	// The next free slot follows the third caller's, 4 steps in.
	ctx, cancel := context.WithDeadline(t.Context(), start.Add(5*step))
	defer cancel()

	require.NoError(t, governor.Wait(ctx, waitHost))
	require.GreaterOrEqual(t, time.Since(start), 4*step, "the next caller follows the last live one")

	got := <-first
	require.NoError(t, got.err)
	require.Less(t, got.at.Sub(start), 2*step, "the first caller kept its slot")

	got = <-third
	require.NoError(t, got.err)
	require.Less(t, got.at.Sub(start), 4*step, "the caller behind a cancelled wait kept its slot")
}

// Decay drops the slots handed out under the old delay, so a wait held from
// before the host recovered does not push back callers once it backs off again.
func TestDecayDropsHeldSlots(t *testing.T) {
	t.Parallel()

	const step = 300 * time.Millisecond

	governor := pacedGovernor(step)

	// This wait keeps its slot, which ends 2 steps from now.
	_, _ = startWait(t, governor)

	governor.Observe(waitHost, http.StatusOK, 0, nil)
	require.Zero(t, governor.Delay(waitHost), "a healthy response clears a one-step delay")
	governor.Observe(waitHost, http.StatusTooManyRequests, 0, nil)

	start := time.Now()

	require.NoError(t, governor.Wait(t.Context(), waitHost))
	require.Less(t, time.Since(start), 3*step/2, "the next caller waits one step, not behind the earlier slot")
}

func TestForbiddenRetryAfterBacksOffImmediately(t *testing.T) {
	g := New(Config{Step: 100 * time.Millisecond, ForbiddenStreak: 5, Max: time.Minute})
	g.Observe("acme.test", http.StatusForbidden, 2*time.Second, nil)
	require.Equal(t, 2*time.Second, g.Delay("acme.test"))
}

func TestNilGovernorIsInert(t *testing.T) {
	var g *Governor
	require.Zero(t, g.Delay("acme.test"))
	require.NoError(t, g.Wait(context.Background(), "acme.test"))
	require.NotPanics(t, func() { g.Observe("acme.test", http.StatusTooManyRequests, 0, nil) })
}

func TestRetryAfterParsing(t *testing.T) {
	require.Equal(t, 5*time.Second, RetryAfter("5"))
	require.Equal(t, 5*time.Second, RetryAfter(" 5 "))
	require.Zero(t, RetryAfter(""))
	require.Zero(t, RetryAfter("not-a-number"))
	require.Zero(t, RetryAfter("-3"), "a negative wait is meaningless")
	require.Zero(t, RetryAfter(time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)), "a date in the past is not a wait")

	future := RetryAfter(time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat))
	require.Greater(t, future, 25*time.Second)
	require.LessOrEqual(t, future, 30*time.Second)
}

// The previous parser appended "s" and called time.ParseDuration, which accepts
// fractional seconds and Go duration strings, and returns an error (then zero)
// when the integer does not fit.
func TestRetryAfterRejectsDurationSyntax(t *testing.T) {
	fractional, err := time.ParseDuration("1.5s")
	require.NoError(t, err)
	require.Equal(t, 1500*time.Millisecond, fractional)
	require.Zero(t, RetryAfter("1.5"))

	compound, err := time.ParseDuration("1m3s")
	require.NoError(t, err)
	require.Equal(t, 63*time.Second, compound)
	require.Zero(t, RetryAfter("1m3"))

	_, err = time.ParseDuration("999999999999999999999s")
	require.Error(t, err)
	require.Equal(t, time.Duration(1<<63-1), RetryAfter("999999999999999999999"))
}

func TestNotFoundDoesNotClearBackoff(t *testing.T) {
	g := New(Config{Step: 100 * time.Millisecond, Decay: 0.5})
	g.Observe("acme.test", http.StatusTooManyRequests, 0, nil)
	g.Observe("acme.test", http.StatusNotFound, 0, nil)
	require.Equal(t, 100*time.Millisecond, g.Delay("acme.test"))

	g.Observe("acme.test", http.StatusInternalServerError, 0, nil)
	require.Equal(t, 100*time.Millisecond, g.Delay("acme.test"))

	g.Observe("acme.test", http.StatusOK, 0, nil)
	require.Zero(t, g.Delay("acme.test"))
}

func TestForbiddenStreakSurvivesAMiss(t *testing.T) {
	g := New(Config{Step: 100 * time.Millisecond, ForbiddenStreak: 3})
	g.Observe("acme.test", http.StatusForbidden, 0, nil)
	g.Observe("acme.test", http.StatusForbidden, 0, nil)
	g.Observe("acme.test", http.StatusNotFound, 0, nil)
	require.Zero(t, g.Delay("acme.test"))

	g.Observe("acme.test", http.StatusForbidden, 0, nil)
	require.Equal(t, 100*time.Millisecond, g.Delay("acme.test"))
}

func TestFailedDialBacksOffAndSuccessfulDialDecays(t *testing.T) {
	g := New(Config{Step: 100 * time.Millisecond, Factor: 2, Decay: 0.5})
	g.ObserveDial("acme.test:22", nil)
	g.ObserveDial("acme.test:22", errors.New("connection refused"))
	g.ObserveDial("acme.test:22", errors.New("connection refused"))
	require.Equal(t, 200*time.Millisecond, g.Delay("acme.test:22"))

	g.ObserveDial("acme.test:22", nil)
	require.Equal(t, 100*time.Millisecond, g.Delay("acme.test:22"))
	g.ObserveDial("acme.test:22", nil)
	require.Zero(t, g.Delay("acme.test:22"))
}

// A port that never accepted is closed or filtered, not pushing back. Slowing
// it would cost every template aimed at it a growing wait for nothing.
func TestDialFailureOnNeverReachedHostIsIgnored(t *testing.T) {
	g := New(Config{Step: 100 * time.Millisecond})
	for i := 0; i < 3; i++ {
		g.ObserveDial("acme.test:22", errors.New("connection refused"))
	}
	require.Zero(t, g.Delay("acme.test:22"))
	_, err := g.hosts.GetIFPresent("acme.test:22")
	require.Error(t, err, "a port that never accepted must not take a cache slot")

	g.ObserveDial("ok.test:22", nil)
	_, err = g.hosts.GetIFPresent("ok.test:22")
	require.NoError(t, err, "a port that accepted is tracked so a later refusal can slow it")
}

func TestResponseMarksHostReachableForDials(t *testing.T) {
	g := New(Config{Step: 100 * time.Millisecond})
	g.Observe("acme.test:443", http.StatusNotFound, 0, nil)
	g.ObserveDial("acme.test:443", errors.New("connection refused"))
	require.Equal(t, 100*time.Millisecond, g.Delay("acme.test:443"))
}
