package httpclientpool

import (
	"bytes"
	"container/list"
	"context"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/useragent"
)

// Templates send many requests another template already sent to the same
// target, byte for byte: clustering merges only single-request templates. A
// request marked with WithSharedResponse is sent once per scan and every
// other template sending the same bytes gets a copy of the response. The key
// is the request as it goes on the wire, cookies included, and the client
// still processes each copy, so redirects and cookies behave as if it was
// sent again.
const (
	// sharedResponseMaxBody keeps large downloads out of the store; they are
	// sent each time
	sharedResponseMaxBody   = 1 << 20
	sharedResponsesMaxBytes = 64 << 20
)

type sharedResponseKey struct{}

// WithSharedResponse marks the request of templateID as one whose response
// other templates may reuse. A template sending the same request again gets
// it sent again: a repeat within one template is intended.
func WithSharedResponse(ctx context.Context, templateID string) context.Context {
	return context.WithValue(ctx, sharedResponseKey{}, templateID)
}

type sharedResponses struct {
	mu      sync.Mutex
	entries map[string]*sharedEntry
	// order holds stored entries oldest first, for eviction
	order    *list.List
	bytes    int
	maxBytes int
}

type sharedEntry struct {
	key        string
	templateID string
	ready      chan struct{}
	response   *storedResponse
}

type storedResponse struct {
	response *http.Response
	body     []byte
}

func getSharedResponses(options *types.Options) *sharedResponses {
	dialers := protocolstate.GetDialersWithId(options.ExecutionId)
	if dialers == nil {
		return nil
	}
	dialers.Lock()
	defer dialers.Unlock()
	if dialers.SharedResponses == nil {
		dialers.SharedResponses = &sharedResponses{entries: make(map[string]*sharedEntry), order: list.New(), maxBytes: sharedResponsesMaxBytes}
	}
	shared, _ := dialers.SharedResponses.(*sharedResponses)
	return shared
}

// ResetSharedResponses forgets the responses of earlier scans, so a scan
// that reuses the execution, as an SDK engine does, sends its requests again.
func ResetSharedResponses(options *types.Options) {
	shared := getSharedResponses(options)
	if shared == nil {
		return
	}
	shared.mu.Lock()
	defer shared.mu.Unlock()
	clear(shared.entries)
	shared.order.Init()
	shared.bytes = 0
}

type sharingTransport struct {
	base   http.RoundTripper
	shared *sharedResponses
}

func (t *sharingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	templateID, marked := req.Context().Value(sharedResponseKey{}).(string)
	if !marked || (req.Method != http.MethodGet && req.Method != http.MethodHead) || hasBody(req) {
		return t.base.RoundTrip(req)
	}
	key := sharedRequestKey(req)

	t.shared.mu.Lock()
	entry, found := t.shared.entries[key]
	if !found {
		entry = &sharedEntry{key: key, templateID: templateID, ready: make(chan struct{})}
		t.shared.entries[key] = entry
		t.shared.mu.Unlock()
		return t.send(req, entry)
	}
	t.shared.mu.Unlock()
	if entry.templateID == templateID {
		return t.base.RoundTrip(req)
	}
	select {
	case <-entry.ready:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	if entry.response == nil {
		// the first send failed or was too large to keep
		return t.base.RoundTrip(req)
	}
	return entry.response.copyFor(req), nil
}

// Unwrap returns the underlying transport, so reporting clients that need TLS
// verification reach the scan transport and never share responses.
func (t *sharingTransport) Unwrap() http.RoundTripper {
	return t.base
}

func (t *sharingTransport) CloseIdleConnections() {
	type closeIdler interface{ CloseIdleConnections() }
	if ci, ok := t.base.(closeIdler); ok {
		ci.CloseIdleConnections()
	}
}

// send sends the first request of key and stores its response for the rest.
func (t *sharingTransport) send(req *http.Request, entry *sharedEntry) (*http.Response, error) {
	defer close(entry.ready)
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		t.forget(entry)
		return resp, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, sharedResponseMaxBody+1))
	if err != nil || len(body) > sharedResponseMaxBody || !shareableStatus(resp.StatusCode) {
		t.forget(entry)
		// The bytes already taken off the body have to go back in front of it.
		// A short read is still this caller's response: a Content-Length that
		// is longer than the body is what some matchers look for. It is not
		// stored, and neither is a body too large to keep or a refusal.
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(body), resp.Body), resp.Body}
		return resp, nil
	}
	_ = resp.Body.Close()
	entry.response = &storedResponse{response: resp, body: body}
	t.store(entry)
	return entry.response.copyFor(req), nil
}

// shareableStatus reports whether code is an answer a later template can
// reuse. 404 and 500 are answers templates match on. 429 and the gateway
// errors mean the server did not answer, so the next template must send.
func shareableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return false
	default:
		return true
	}
}

// hasBody reports whether req sends a body. retryablehttp gives every
// request one, empty for a GET, so its content is what counts.
func hasBody(req *http.Request) bool {
	if req.Body == nil || req.Body == http.NoBody {
		return false
	}
	if req.ContentLength > 0 || req.GetBody == nil {
		return true
	}
	body, err := req.GetBody()
	if err != nil {
		return true
	}
	defer func() { _ = body.Close() }()
	var first [1]byte
	n, _ := body.Read(first[:])
	return n > 0
}

func (t *sharingTransport) forget(entry *sharedEntry) {
	t.shared.mu.Lock()
	defer t.shared.mu.Unlock()
	if t.shared.entries[entry.key] == entry {
		delete(t.shared.entries, entry.key)
	}
}

func (t *sharingTransport) store(entry *sharedEntry) {
	t.shared.mu.Lock()
	defer t.shared.mu.Unlock()
	// a reset while it was in flight dropped it
	if t.shared.entries[entry.key] != entry {
		return
	}
	t.shared.order.PushBack(entry)
	t.shared.bytes += entry.size()
	for t.shared.bytes > t.shared.maxBytes && t.shared.order.Len() > 1 {
		oldest := t.shared.order.Remove(t.shared.order.Front()).(*sharedEntry)
		t.shared.bytes -= oldest.size()
		if t.shared.entries[oldest.key] == oldest {
			delete(t.shared.entries, oldest.key)
		}
	}
}

// sharedEntryOverhead stands for the response struct and bookkeeping, so
// bodyless responses, as every HEAD gets, still count toward the cap.
const sharedEntryOverhead = 512

func (e *sharedEntry) size() int {
	size := sharedEntryOverhead + len(e.key) + len(e.response.body)
	for name, values := range e.response.response.Header {
		size += len(name)
		for _, value := range values {
			size += len(value)
		}
	}
	return size
}

func (s *storedResponse) copyFor(req *http.Request) *http.Response {
	resp := *s.response
	resp.Header = s.response.Header.Clone()
	resp.Trailer = s.response.Trailer.Clone()
	resp.Body = io.NopCloser(bytes.NewReader(s.body))
	// A HEAD response has an empty body and a Content-Length for the body it
	// did not send. Matchers read that length, so a reused HEAD keeps it.
	if req.Method != http.MethodHead {
		resp.ContentLength = int64(len(s.body))
	}
	resp.Request = req
	return &resp
}

// randomUserAgents are the values nuclei picks a User-Agent from for every
// request a template does not set one for. Two templates sending the same
// request almost never pick the same one, and either could have picked the
// other's, so a picked User-Agent is left out of the key.
var randomUserAgents = sync.OnceValue(func() map[string]struct{} {
	values := make(map[string]struct{}, len(useragent.UserAgents))
	for _, userAgent := range useragent.UserAgents {
		values[userAgent.Raw] = struct{}{}
	}
	return values
})

// sharedRequestKey is the request as the server receives it, apart from the
// order of headers and a picked User-Agent.
func sharedRequestKey(req *http.Request) string {
	var key strings.Builder
	key.WriteString(req.Method)
	key.WriteByte(' ')
	key.WriteString(req.URL.String())
	key.WriteByte('\n')
	key.WriteString(req.Host)
	for _, name := range slices.Sorted(maps.Keys(req.Header)) {
		values := req.Header[name]
		if _, picked := randomUserAgents()[req.Header.Get("User-Agent")]; name == "User-Agent" && len(values) == 1 && picked {
			continue
		}
		for _, value := range values {
			key.WriteByte('\n')
			key.WriteString(name)
			key.WriteString(": ")
			key.WriteString(value)
		}
	}
	return key.String()
}
