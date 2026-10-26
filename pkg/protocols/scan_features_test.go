package protocols

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httprespcache"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestAttachScanFeaturesDefaults(t *testing.T) {
	e := &ExecutorOptions{Options: &types.Options{}}
	e.AttachScanFeatures()
	if e.HTTPService == nil || e.HostLimit == nil || e.StreamLimit == nil {
		t.Fatalf("defaults must attach placement and adaptive concurrency: %+v", e)
	}
	if e.HTTPResponseCache != nil {
		t.Fatal("the response cache is opt-in")
	}
}

func TestAttachScanFeaturesResponseCacheOptIn(t *testing.T) {
	e := &ExecutorOptions{Options: &types.Options{ResponseCache: true}}
	e.AttachScanFeatures()
	if e.HTTPResponseCache == nil {
		t.Fatal("-response-cache must attach the cache")
	}
}

func TestAttachScanFeaturesHonoursDisable(t *testing.T) {
	e := &ExecutorOptions{Options: &types.Options{
		DisableServicePlacement:    true,
		DisableAdaptiveConcurrency: true,
	}}
	e.AttachScanFeatures()
	if e.HTTPService != nil || e.HostLimit != nil || e.StreamLimit != nil || e.HTTPResponseCache != nil {
		t.Fatal("disabled features must stay off")
	}
}

// A long-lived engine keeps the instances (templates may hold a copy of the
// options) and only empties their per-scan content.
func TestResetScanStateEmptiesSharedCache(t *testing.T) {
	e := &ExecutorOptions{Options: &types.Options{ResponseCache: true}}
	e.AttachScanFeatures()
	cache := e.HTTPResponseCache
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	cache.Set(httprespcache.KeyFromRequest(req), "", &http.Response{StatusCode: 200, Header: http.Header{}}, []byte("x"))
	if cache.Len() != 1 {
		t.Fatal("setup: entry not stored")
	}
	e.ResetScanState()
	if e.HTTPResponseCache != cache {
		t.Fatal("reset must keep the same instance")
	}
	if cache.Len() != 0 {
		t.Fatal("reset must drop cached responses")
	}
}

func TestScanFeatureHelpersOnNil(t *testing.T) {
	var e *ExecutorOptions
	e.AttachScanFeatures()
	e.ResetScanState()
	(&ExecutorOptions{}).AttachScanFeatures()
	(&ExecutorOptions{}).ResetScanState()
}
