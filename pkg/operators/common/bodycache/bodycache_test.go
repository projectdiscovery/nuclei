package bodycache

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFrom_CreatesAndReuses(t *testing.T) {
	data := map[string]interface{}{}
	c1 := From(data)
	require.NotNil(t, c1)
	c2 := From(data)
	require.Same(t, c1, c2, "From must return the cached instance stored on the map")

	// nil map is tolerated and yields a throwaway cache.
	require.NotNil(t, From(nil))
}

func TestFrom_IgnoresWrongType(t *testing.T) {
	data := map[string]interface{}{Key: "not-a-cache"}
	c := From(data)
	require.NotNil(t, c)
	if _, ok := data[Key].(*Cache); !ok {
		t.Fatalf("From must overwrite a non-*Cache value at Key with a real cache")
	}
}

func TestCache_HTMLMemoizesSameCorpus(t *testing.T) {
	c := &Cache{}
	const corpus = `<html><body><a href="x">link</a></body></html>`
	doc1, err1 := c.HTMLNode(corpus)
	doc2, err2 := c.HTMLNode(corpus)
	require.NoError(t, err1)
	require.NoError(t, err2)
	require.Same(t, doc1, doc2, "same corpus must return the memoized parse")
}

func TestCache_HTMLReparsesOnCorpusChange(t *testing.T) {
	c := &Cache{}
	doc1, _ := c.HTMLNode(`<html><body>a</body></html>`)
	doc2, _ := c.HTMLNode(`<html><body>b</body></html>`)
	require.NotSame(t, doc1, doc2, "a different corpus must invalidate and re-parse")
}

func TestCache_JSONMemoizesAndReportsError(t *testing.T) {
	c := &Cache{}
	obj1, err1 := c.JSONObject(`{"a":1}`)
	obj2, err2 := c.JSONObject(`{"a":1}`)
	require.NoError(t, err1)
	require.NoError(t, err2)
	require.Equal(t, obj1, obj2)

	_, err := c.JSONObject(`{not-json`)
	require.Error(t, err, "invalid JSON must surface the unmarshal error")
}

func TestCache_Lowered(t *testing.T) {
	c := &Cache{}
	require.Equal(t, "abc", c.Lowered("ABC"))
	require.Equal(t, "abc", c.Lowered("ABC"), "second call hits the memoized result")
	require.Equal(t, "xyz", c.Lowered("XYZ"), "different corpus re-lowers")
}

// TestCache_ConcurrentAccess exercises the mutex: a single cache instance hit
// from many goroutines (the interactsh re-evaluation shape) must not race or
// panic. Run with -race to validate.
func TestCache_ConcurrentAccess(t *testing.T) {
	c := &Cache{}
	const corpus = `<html><body><div id="a">x</div></body></html>`

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.HTMLNode(corpus)
			_, _ = c.JSONObject(`{"k":"v"}`)
			_ = c.Lowered("MiXeD")
		}()
	}
	wg.Wait()
}
