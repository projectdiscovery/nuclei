package httprespcache

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

func okResponse() *http.Response {
	return &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Server": []string{"nginx"}},
		Body:       io.NopCloser(http.NoBody),
	}
}

// startWaiters runs n GetOrLead calls from distinct owners and returns their
// results once all of them return.
func startWaiters(c *Cache, key string, n int, req *http.Request) (results chan *http.Response, returned chan struct{}) {
	results = make(chan *http.Response, n)
	returned = make(chan struct{}, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			resp, done := c.GetOrLead(key, "waiter-"+strconv.Itoa(i), req)
			done()
			returned <- struct{}{}
			results <- resp
		}(i)
	}
	return results, returned
}

// Concurrent identical requests send one request: the others wait for the
// leader and each gets its own response and body reader.
func TestInFlightShared(t *testing.T) {
	c := New()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	key := KeyFromRequest(req)

	resp, done := c.GetOrLead(key, "leader", req)
	if resp != nil {
		t.Fatal("first request must lead, not hit")
	}
	const n = 16
	results, returned := startWaiters(c, key, n, req)

	select {
	case <-returned:
		t.Fatal("a waiter returned before the leader finished")
	case <-time.After(50 * time.Millisecond):
	}

	c.Set(key, "leader", okResponse(), []byte("shared body"))
	done()
	done() // safe to call twice

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		got := <-results
		if got == nil {
			t.Fatal("waiter got no response")
		}
		wg.Add(1)
		go func(r *http.Response) {
			defer wg.Done()
			body, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			if string(body) != "shared body" {
				t.Errorf("body=%q", body)
			}
			r.Header.Set("Server", "changed")
		}(got)
	}
	wg.Wait()
	hits, misses, stores := c.Stats()
	if hits != n || misses != 1 || stores != 1 {
		t.Fatalf("stats hits=%d misses=%d stores=%d", hits, misses, stores)
	}
	again, _ := c.GetOrLead(key, "late", req)
	if again == nil || again.Header.Get("Server") != "nginx" {
		t.Fatal("a waiter must not change the stored entry")
	}
}

// A leader that stores nothing (error, uncacheable response) shares nothing:
// waiters get nil and send their own request, and nothing is cached.
func TestInFlightErrorNotShared(t *testing.T) {
	c := New()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	key := KeyFromRequest(req)

	_, done := c.GetOrLead(key, "leader", req)
	results, _ := startWaiters(c, key, 4, req)
	time.Sleep(20 * time.Millisecond)
	done()
	for i := 0; i < 4; i++ {
		if <-results != nil {
			t.Fatal("a failed leader must not share a response")
		}
	}
	if c.Len() != 0 {
		t.Fatal("nothing must be cached")
	}
	if resp, done := c.GetOrLead(key, "later", req); resp != nil {
		t.Fatal("a later caller must send its own request")
	} else {
		done()
	}
}

// A response over the size limit is not stored, so it is not shared either.
func TestInFlightRespectsSizeLimit(t *testing.T) {
	c := New()
	c.maxBytes = 8
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	key := KeyFromRequest(req)

	_, done := c.GetOrLead(key, "leader", req)
	results, _ := startWaiters(c, key, 2, req)
	time.Sleep(20 * time.Millisecond)
	c.Set(key, "leader", okResponse(), []byte("a body larger than the limit"))
	done()
	for i := 0; i < 2; i++ {
		if <-results != nil {
			t.Fatal("an entry over the limit must not be shared")
		}
	}
}

// The owner rule holds in flight: a template never waits for its own request.
func TestInFlightNotSharedWithOwner(t *testing.T) {
	c := New()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	key := KeyFromRequest(req)

	_, done := c.GetOrLead(key, "same", req)
	defer done()
	returned := make(chan *http.Response, 1)
	go func() {
		resp, d := c.GetOrLead(key, "same", req)
		d()
		returned <- resp
	}()
	select {
	case resp := <-returned:
		if resp != nil {
			t.Fatal("a template must not get its own response")
		}
	case <-time.After(time.Second):
		t.Fatal("a template must not wait for its own request")
	}
}

// A canceled request stops waiting.
func TestInFlightWaitHonorsContext(t *testing.T) {
	c := New()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	key := KeyFromRequest(req)

	_, done := c.GetOrLead(key, "leader", req)
	defer done()
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan *http.Response, 1)
	go func() {
		resp, d := c.GetOrLead(key, "waiter", req.WithContext(ctx))
		d()
		returned <- resp
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case resp := <-returned:
		if resp != nil {
			t.Fatal("a canceled waiter must get nil")
		}
	case <-time.After(time.Second):
		t.Fatal("a canceled waiter must stop waiting")
	}
}
