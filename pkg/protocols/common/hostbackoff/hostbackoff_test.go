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
