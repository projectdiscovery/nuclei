package httprespcache

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCacheRoundTrip(t *testing.T) {
	c := New()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Server": []string{"nginx"}},
		Body:       io.NopCloser(http.NoBody),
	}
	c.Set(KeyFromRequest(req), "", resp, []byte("ok"))

	got := c.Get(KeyFromRequest(req), "", req)
	if got == nil {
		t.Fatal("expected cache hit")
	}
	body, _ := io.ReadAll(got.Body)
	if string(body) != "ok" {
		t.Fatalf("body=%q", body)
	}
	if got.Header.Get("Server") != "nginx" {
		t.Fatalf("header=%v", got.Header)
	}
	hits, misses, stores := c.Stats()
	if hits != 1 || misses != 0 || stores != 1 {
		t.Fatalf("stats hits=%d misses=%d stores=%d", hits, misses, stores)
	}
	if c.Get(Key(http.MethodGet, "http://example.com/other"), "", req) != nil {
		t.Fatal("expected miss")
	}
}

func TestCacheableRequest(t *testing.T) {
	get := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	if !CacheableRequest(get) {
		t.Fatal("GET should be cacheable")
	}
	post := httptest.NewRequest(http.MethodPost, "http://x/", nil)
	if CacheableRequest(post) {
		t.Fatal("POST should not be cacheable")
	}
	auth := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	auth.Header.Set("Authorization", "Bearer t")
	if CacheableRequest(auth) {
		t.Fatal("Authorization must not be cacheable")
	}
	cookie := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	cookie.Header.Set("Cookie", "a=b")
	if CacheableRequest(cookie) {
		t.Fatal("Cookie must not be cacheable")
	}
	hostOverride := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	hostOverride.Host = "other.example"
	if CacheableRequest(hostOverride) {
		t.Fatal("Host override must not be cacheable")
	}
	cc := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	cc.Header.Set("Cache-Control", "no-cache")
	if CacheableRequest(cc) {
		t.Fatal("Cache-Control must not be cacheable")
	}
	pragma := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	pragma.Header.Set("Pragma", "no-cache")
	if CacheableRequest(pragma) {
		t.Fatal("Pragma must not be cacheable")
	}
}

func TestKeyFromRequestIncludesRepresentationHeaders(t *testing.T) {
	a := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	a.Header.Set("User-Agent", "ua-a")
	a.Header.Set("Accept-Language", "en")

	b := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	b.Header.Set("User-Agent", "ua-a")
	b.Header.Set("Accept-Language", "fr")

	if KeyFromRequest(a) == KeyFromRequest(b) {
		t.Fatal("distinct Accept-Language must produce distinct keys")
	}

	c := New()
	c.Set(KeyFromRequest(a), "", &http.Response{StatusCode: 200, Header: http.Header{}}, []byte("en-body"))
	if c.Get(KeyFromRequest(b), "", b) != nil {
		t.Fatal("must not reuse response across Accept-Language")
	}
	if got := c.Get(KeyFromRequest(a), "", a); got == nil {
		t.Fatal("expected hit for matching headers")
	}
}

func TestCacheDisabled(t *testing.T) {
	c := New()
	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Set(KeyFromRequest(req), "", &http.Response{StatusCode: 200, Header: http.Header{}}, []byte("x"))
	c.Disable()
	if c.Get(KeyFromRequest(req), "", req) != nil {
		t.Fatal("disabled cache must miss")
	}
	c.Set(KeyFromRequest(req), "", &http.Response{StatusCode: 200, Header: http.Header{}}, []byte("y"))
	if c.Enabled() {
		t.Fatal("expected disabled")
	}
}

func TestCacheEntryBudget(t *testing.T) {
	c := New()
	c.maxEntries = 2
	c.maxBytes = 100
	mk := func(path, body string) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil)
		c.Set(KeyFromRequest(req), "", &http.Response{StatusCode: 200, Header: http.Header{}}, []byte(body))
	}
	mk("/a", "aa")
	mk("/b", "bb")
	mk("/c", "cc") // over entry budget
	if c.Len() != 2 {
		t.Fatalf("len=%d want 2", c.Len())
	}
	if c.skipped.Load() == 0 {
		t.Fatal("expected skipped store")
	}

	c2 := New()
	c2.maxEntries = 10
	// The budget covers key, headers and body: room for "/a" with a 5-byte body.
	c2.maxBytes = int64(len(KeyFromRequest(httptest.NewRequest(http.MethodGet, "http://example.com/a", nil)))) + 5
	mk2 := func(path, body string) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil)
		c2.Set(KeyFromRequest(req), "", &http.Response{StatusCode: 200, Header: http.Header{}}, []byte(body))
	}
	mk2("/a", "12345")
	mk2("/b", "x") // over byte budget
	if c2.Len() != 1 {
		t.Fatalf("byte budget len=%d want 1", c2.Len())
	}
}

func TestCacheableRequestEmptyBody(t *testing.T) {
	// Raw templates hand over a non-nil but empty reader with ContentLength 0.
	// That request is bodyless on the wire, so it stays cacheable.
	empty := httptest.NewRequest(http.MethodGet, "http://x/", strings.NewReader(""))
	empty.ContentLength = 0
	if empty.Body == nil {
		t.Fatal("test needs a non-nil body")
	}
	if !CacheableRequest(empty) {
		t.Fatal("GET with an empty body should be cacheable")
	}

	// A GET that really carries bytes is excluded: the body is part of the
	// request identity but is not part of the cache key.
	withBody := httptest.NewRequest(http.MethodGet, "http://x/", strings.NewReader("payload"))
	withBody.ContentLength = int64(len("payload"))
	if CacheableRequest(withBody) {
		t.Fatal("GET with a payload must not be cacheable")
	}

	// Unknown length is treated as a payload.
	unknown := httptest.NewRequest(http.MethodGet, "http://x/", strings.NewReader("payload"))
	unknown.ContentLength = -1
	if CacheableRequest(unknown) {
		t.Fatal("GET with an unknown body length must not be cacheable")
	}
}

func TestCacheableRequestHostHeader(t *testing.T) {
	// Raw templates repeat the target host in a Host header. net/http drops it
	// and sends the URL host, so the request is unchanged and stays cacheable.
	same := httptest.NewRequest(http.MethodGet, "http://x.example/", nil)
	same.Header.Set("Host", "x.example")
	if !CacheableRequest(same) {
		t.Fatal("redundant Host header should stay cacheable")
	}

	withDefaultPort := httptest.NewRequest(http.MethodGet, "http://x.example/", nil)
	withDefaultPort.Header.Set("Host", "x.example:80")
	if !CacheableRequest(withDefaultPort) {
		t.Fatal("Host header with the default port should stay cacheable")
	}

	// A different Host is a deliberate override and must not share a response.
	other := httptest.NewRequest(http.MethodGet, "http://x.example/", nil)
	other.Header.Set("Host", "evil.example")
	if CacheableRequest(other) {
		t.Fatal("Host override must not be cacheable")
	}

	otherPort := httptest.NewRequest(http.MethodGet, "http://x.example/", nil)
	otherPort.Header.Set("Host", "x.example:8080")
	if CacheableRequest(otherPort) {
		t.Fatal("Host header with a different port must not be cacheable")
	}
}

func TestCacheReset(t *testing.T) {
	c := New()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	c.Set(KeyFromRequest(req), "", &http.Response{StatusCode: 200, Header: http.Header{}}, []byte("body"))
	c.Get(KeyFromRequest(req), "", req)
	c.Reset()
	if c.Len() != 0 {
		t.Fatal("Reset must drop entries")
	}
	if h, m, s := c.Stats(); h != 0 || m != 0 || s != 0 {
		t.Fatalf("Reset must clear counters: %d %d %d", h, m, s)
	}
	c.Set(KeyFromRequest(req), "", &http.Response{StatusCode: 200, Header: http.Header{}}, []byte("body"))
	if c.Len() != 1 {
		t.Fatal("cache must stay usable after Reset")
	}
}

// A template that repeats its own request means it, so the repeat must reach
// the server; other templates still share the response.
func TestCacheNotServedBackToOwner(t *testing.T) {
	c := New()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	key := KeyFromRequest(req)
	c.Set(key, "template-a", &http.Response{StatusCode: 200, Header: http.Header{}}, []byte("1"))
	if c.Get(key, "template-a", req) != nil {
		t.Fatal("an entry must not be served back to the template that stored it")
	}
	if c.Get(key, "template-b", req) == nil {
		t.Fatal("another template must reuse the entry")
	}
}

func ok200() *http.Response { return &http.Response{StatusCode: 200, Header: http.Header{}} }

// Each template gets at most one cached answer per request: its repeat reaches
// the server even when the entry was stored by someone else.
func TestAtMostOneCachedAnswerPerTemplate(t *testing.T) {
	c := New()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	key := KeyFromRequest(req)
	c.Set(key, "a", ok200(), []byte("1"))
	if c.Get(key, "b", req) == nil {
		t.Fatal("first lookup by another template should hit")
	}
	if c.Get(key, "b", req) != nil {
		t.Fatal("the same template's repeat must reach the server")
	}
}

// A template that already sent a request (miss) must not later be answered from
// an entry another template stored in between.
func TestRepeatAfterOthersStoreStillMisses(t *testing.T) {
	c := New()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	key := KeyFromRequest(req)
	if c.Get(key, "a", req) != nil {
		t.Fatal("empty cache must miss")
	}
	c.Set(key, "b", ok200(), []byte("1"))
	if c.Get(key, "a", req) != nil {
		t.Fatal("a template that already sent this request must not be served")
	}
}

// When the record of seen pairs is full, nothing is served.
func TestFullSeenRecordStopsHits(t *testing.T) {
	c := New()
	c.maxSeen = 1
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	key := KeyFromRequest(req)
	c.Set(key, "a", ok200(), []byte("1")) // fills the record
	if c.Get(key, "b", req) != nil {
		t.Fatal("a full record must stop hits")
	}
}

// Headers and key count against the memory budget, not only the body.
func TestBudgetCountsHeaders(t *testing.T) {
	c := New()
	c.maxBytes = 512
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	resp := ok200()
	resp.Header.Set("X-Big", strings.Repeat("h", 1024))
	c.Set(KeyFromRequest(req), "a", resp, []byte("tiny"))
	if c.Len() != 0 {
		t.Fatal("an entry whose headers exceed the budget must not be stored")
	}
}

func TestReplayableEncoding(t *testing.T) {
	h := func(enc string) http.Header { x := http.Header{}; x.Set("Content-Encoding", enc); return x }
	cases := []struct {
		name string
		h    http.Header
		body []byte
		want bool
	}{
		{"no encoding", http.Header{}, []byte("x"), true},
		{"identity", h("identity"), []byte("x"), true},
		{"gzip, plain decoded body", h("gzip"), []byte("<html>"), true},
		{"gzip, decoded body is gzip again", h("gzip"), []byte{0x1f, 0x8b, 0x08}, false},
		{"deflate", h("deflate"), []byte("x"), false},
		{"brotli", h("br"), []byte("x"), false},
		{"zstd", h("zstd"), []byte("x"), false},
	}
	for _, tc := range cases {
		if got := ReplayableEncoding(tc.h, tc.body); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestStoredStatus(t *testing.T) {
	for code, want := range map[int]bool{200: true, 301: true, 404: true, 400: true, 408: false, 429: false, 500: false, 503: false} {
		if got := StoredStatus(code); got != want {
			t.Errorf("StoredStatus(%d)=%v want %v", code, got, want)
		}
	}
}

func TestCompleteBody(t *testing.T) {
	cases := []struct {
		name  string
		body  int
		limit int64
		want  bool
	}{
		{"shorter than limit", 10, 50, true},
		{"fills limit, may be cut", 50, 50, false},
		{"no limit", 50, 0, true},
	}
	for _, tc := range cases {
		if got := CompleteBody(make([]byte, tc.body), tc.limit); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestSeedHTTPSkipsCutBody(t *testing.T) {
	c := New()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}

	c.SeedHTTP(req, resp, []byte("12345"), 5)
	if c.Len() != 0 {
		t.Fatal("a body that fills the probe limit must not be seeded")
	}
	c.SeedHTTP(req, resp, []byte("1234"), 5)
	if c.Len() != 1 {
		t.Fatal("a complete body must be seeded")
	}
}
