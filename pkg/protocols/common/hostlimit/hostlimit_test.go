package hostlimit

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// In-flight requests per endpoint never exceed the limit.
func TestNeverExceedsLimit(t *testing.T) {
	l := New(Config{Initial: 4, Min: 4, Max: 4, Window: 1000})
	var cur, peak atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tk, err := l.Acquire(context.Background(), "h:80")
			if err != nil {
				t.Error(err)
				return
			}
			n := cur.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			cur.Add(-1)
			tk.Release(Outcome{})
		}()
	}
	wg.Wait()
	if peak.Load() > 4 {
		t.Fatalf("peak in flight %d > limit 4", peak.Load())
	}
}

// Endpoints are independent: a saturated one does not block another.
func TestEndpointsAreIndependent(t *testing.T) {
	l := New(Config{Initial: 2, Min: 2, Max: 2})
	a1, _ := l.Acquire(context.Background(), "a:80")
	a2, _ := l.Acquire(context.Background(), "a:80")
	done := make(chan struct{})
	go func() {
		b, err := l.Acquire(context.Background(), "b:80")
		if err == nil {
			b.Release(Outcome{})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("endpoint b was blocked by endpoint a")
	}
	a1.Release(Outcome{})
	a2.Release(Outcome{})
}

// A healthy endpoint that uses its whole limit grows.
func TestGrowsWhileHealthy(t *testing.T) {
	l := New(Config{Initial: 4, Min: 2, Max: 64, Window: 4})
	for round := 0; round < 20; round++ {
		var tks []*Ticket
		for i := 0; i < l.Limit("h:80"); i++ {
			tk, _ := l.Acquire(context.Background(), "h:80")
			tks = append(tks, tk)
		}
		for _, tk := range tks {
			tk.Release(Outcome{Sample: true, Latency: 10 * time.Millisecond})
		}
	}
	if got := l.Limit("h:80"); got <= 4 {
		t.Fatalf("limit did not grow on a healthy saturated endpoint: %d", got)
	}
}

// An overload error halves the limit at once.
func TestCutsOnOverload(t *testing.T) {
	l := New(Config{Initial: 40, Min: 2, Max: 64})
	tk, _ := l.Acquire(context.Background(), "h:80")
	tk.Release(Outcome{Overload: true})
	if got := l.Limit("h:80"); got != 20 {
		t.Fatalf("limit after overload = %d want 20", got)
	}
}

// Rising latency cuts the limit even without errors.
func TestCutsOnRisingLatency(t *testing.T) {
	l := New(Config{Initial: 32, Min: 2, Max: 64, Window: 4})
	feed := func(lat time.Duration) {
		for i := 0; i < 4; i++ {
			tk, _ := l.Acquire(context.Background(), "h:80")
			tk.Release(Outcome{Sample: true, Latency: lat})
		}
	}
	feed(10 * time.Millisecond) // baseline
	before := l.Limit("h:80")
	feed(100 * time.Millisecond) // 10x the baseline
	if got := l.Limit("h:80"); got >= before {
		t.Fatalf("limit did not drop on rising latency: before=%d after=%d", before, got)
	}
}

// Slow-by-design requests do not feed the signal.
func TestNonSampleLatencyIgnored(t *testing.T) {
	l := New(Config{Initial: 32, Min: 2, Max: 64, Window: 4})
	for i := 0; i < 4; i++ {
		tk, _ := l.Acquire(context.Background(), "h:80")
		tk.Release(Outcome{Sample: true, Latency: 10 * time.Millisecond})
	}
	before := l.Limit("h:80")
	for i := 0; i < 40; i++ {
		tk, _ := l.Acquire(context.Background(), "h:80")
		tk.Release(Outcome{Sample: false, Latency: 15 * time.Second})
	}
	if got := l.Limit("h:80"); got < before {
		t.Fatalf("slow-by-design requests cut the limit: before=%d after=%d", before, got)
	}
}

// A waiter whose context ends leaves the queue and does not leak a slot.
func TestCancelledWaiterDoesNotLeak(t *testing.T) {
	l := New(Config{Initial: 1, Min: 1, Max: 1})
	held, _ := l.Acquire(context.Background(), "h:80")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := l.Acquire(ctx, "h:80"); err == nil {
		t.Fatal("expected context error")
	}
	held.Release(Outcome{})
	got, err := l.Acquire(context.Background(), "h:80")
	if err != nil {
		t.Fatal(err)
	}
	got.Release(Outcome{})
}

// Releasing twice is harmless.
func TestDoubleReleaseIsSafe(t *testing.T) {
	l := New(Config{Initial: 1, Min: 1, Max: 1})
	tk, _ := l.Acquire(context.Background(), "h:80")
	tk.Release(Outcome{})
	tk.Release(Outcome{})
	tk2, _ := l.Acquire(context.Background(), "h:80")
	done := make(chan struct{})
	go func() {
		tk3, _ := l.Acquire(context.Background(), "h:80")
		tk3.Release(Outcome{})
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("a double release created an extra slot")
	case <-time.After(50 * time.Millisecond):
	}
	tk2.Release(Outcome{})
	<-done
}

func TestNilLimiter(t *testing.T) {
	var l *Limiter
	tk, err := l.Acquire(context.Background(), "h:80")
	if err != nil {
		t.Fatal(err)
	}
	tk.Release(Outcome{})
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestIsOverload(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{context.Canceled, false},
		{context.DeadlineExceeded, true},
		{timeoutErr{}, true},
		{errors.New("read tcp: connection reset by peer"), true},
		{errors.New("dial tcp 127.0.0.1:445: connect: connection refused"), true},
		{io.ErrUnexpectedEOF, true},
		{errors.New("tls: handshake failure"), false},
		{errors.New("could not evaluate template expressions"), false},
	}
	for _, c := range cases {
		if got := IsOverload(c.err); got != c.want {
			t.Errorf("IsOverload(%v)=%v want %v", c.err, got, c.want)
		}
	}
}
