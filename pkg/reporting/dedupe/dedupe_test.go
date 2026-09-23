package dedupe

import (
	"crypto/sha1"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func TestDedupeDistinctInputs(t *testing.T) {
	base := output.ResultEvent{
		TemplateID: "gitlab-detect",
		Type:       "http",
		Host:       "example.com",
		Port:       "80",
		Scheme:     "http",
		URL:        "http://example.com:80",
		Matched:    "https://example.com:443/users/sign_in",
	}
	tests := []struct {
		name   string
		change func(*output.ResultEvent)
	}{
		{"redirected origins", func(event *output.ResultEvent) {
			event.Port = "443"
			event.Scheme = "https"
			event.URL = "https://example.com:443"
		}},
		{"port", func(event *output.ResultEvent) { event.Port = "8080" }},
		{"scheme", func(event *output.ResultEvent) { event.Scheme = "https" }},
		{"url", func(event *output.ResultEvent) { event.URL += "/other" }},
		{"template", func(event *output.ResultEvent) { event.TemplateID = "other" }},
		{"matcher", func(event *output.ResultEvent) { event.MatcherName = "other" }},
		{"extractor", func(event *output.ResultEvent) { event.ExtractorName = "other" }},
		{"protocol", func(event *output.ResultEvent) { event.Type = "headless" }},
		{"host", func(event *output.ResultEvent) { event.Host = "other.example.com" }},
		{"matched", func(event *output.ResultEvent) { event.Matched += "/other" }},
		{"extracted results", func(event *output.ResultEvent) { event.ExtractedResults = []string{"other"} }},
		{"metadata", func(event *output.ResultEvent) { event.Metadata = map[string]interface{}{"payload": "other"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage, err := New(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(storage.Close)
			other := base
			tt.change(&other)
			for _, event := range []*output.ResultEvent{&base, &other} {
				unique, err := storage.Index(event)
				require.NoError(t, err)
				require.True(t, unique, "distinct input must be retained")
			}
			for _, event := range []*output.ResultEvent{&base, &other} {
				unique, err := storage.Index(event)
				require.NoError(t, err)
				require.False(t, unique, "repeat finding must be suppressed")
			}
		})
	}
}

func TestDedupeConcurrentDuplicates(t *testing.T) {
	storage, err := New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(storage.Close)
	const workers = 32
	for trial := range 20 {
		event := output.ResultEvent{TemplateID: strconv.Itoa(trial), Host: "example.com"}
		start := make(chan struct{})
		var wg sync.WaitGroup
		var accepted atomic.Int32
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				unique, err := storage.Index(&event)
				if err != nil {
					t.Errorf("index concurrent finding: %v", err)
					return
				}
				if unique {
					accepted.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		require.EqualValues(t, 1, accepted.Load(), "trial %d must accept exactly one copy", trial)
	}
}

func TestDedupeMetadataOrder(t *testing.T) {
	storage, err := New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(storage.Close)
	event := output.ResultEvent{
		TemplateID: "test", Host: "example.com",
		Metadata: map[string]interface{}{"username": "admin", "password": "test", "path": "/login"},
	}
	for i := range 100 {
		unique, err := storage.Index(&event)
		require.NoError(t, err)
		require.Equal(t, i == 0, unique, "metadata order must not change finding identity")
	}
}

func TestDedupeFieldBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		first output.ResultEvent
		next  output.ResultEvent
	}{
		{"matcher", output.ResultEvent{TemplateID: "ab", MatcherName: "c"}, output.ResultEvent{TemplateID: "a", MatcherName: "bc"}},
		{"extracts", output.ResultEvent{ExtractedResults: []string{"ab", "c"}}, output.ResultEvent{ExtractedResults: []string{"a", "bc"}}},
		{"metadata", output.ResultEvent{Metadata: map[string]interface{}{"ab": "c"}}, output.ResultEvent{Metadata: map[string]interface{}{"a": "bc"}}},
		{"collections", output.ResultEvent{ExtractedResults: []string{"a", "b"}}, output.ResultEvent{Metadata: map[string]interface{}{"a": "b"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage, err := New(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(storage.Close)
			for _, event := range []*output.ResultEvent{&tt.first, &tt.next} {
				event.Host = "example.com"
				unique, err := storage.Index(event)
				require.NoError(t, err)
				require.True(t, unique, "field boundaries must distinguish findings")
			}
		})
	}
}

func TestDedupePersistence(t *testing.T) {
	dir := t.TempDir()
	storage, err := New(dir)
	require.NoError(t, err)
	t.Cleanup(storage.Close)
	// Legacy keys cannot distinguish these two input origins.
	legacy := sha1.Sum([]byte("testhttpexample.comhttps://example.com/login"))
	require.NoError(t, storage.storage.Put(legacy[:], nil, nil))
	events := []output.ResultEvent{
		{TemplateID: "test", Type: "http", Host: "example.com", Port: "80", Scheme: "http", URL: "http://example.com", Matched: "https://example.com/login"},
		{TemplateID: "test", Type: "http", Host: "example.com", Port: "443", Scheme: "https", URL: "https://example.com", Matched: "https://example.com/login"},
	}
	for _, event := range events {
		unique, err := storage.Index(&event)
		require.NoError(t, err)
		require.True(t, unique, "legacy key must not suppress an input origin")
	}
	storage.Close()
	storage, err = New(dir)
	require.NoError(t, err)
	t.Cleanup(storage.Close)
	for _, event := range events {
		unique, err := storage.Index(&event)
		require.NoError(t, err)
		require.False(t, unique, "new keys must persist across reopen")
	}
}

func TestDedupeStorageErrorPreservesFinding(t *testing.T) {
	storage, err := New(t.TempDir())
	require.NoError(t, err)
	storage.Close()
	unique, err := storage.Index(&output.ResultEvent{TemplateID: "test", Host: "example.com"})
	require.Error(t, err)
	require.True(t, unique, "storage errors must not discard findings")
}

func BenchmarkDedupeIndex(b *testing.B) {
	for _, unique := range []bool{false, true} {
		name := "duplicates"
		if unique {
			name = "unique"
		}
		b.Run(name, func(b *testing.B) {
			storage, err := New(b.TempDir())
			require.NoError(b, err)
			b.Cleanup(storage.Close)
			base := output.ResultEvent{
				TemplateID: "gitlab-detect", Type: "http", Host: "example.com",
				Port: "443", Scheme: "https", URL: "https://example.com:443",
				Matched: "https://example.com:443/users/sign_in",
			}
			_, err = storage.Index(&base)
			require.NoError(b, err)
			var next atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				event := base
				for pb.Next() {
					if unique {
						event.Matched = strconv.FormatUint(next.Add(1), 10)
					}
					if _, err := storage.Index(&event); err != nil {
						b.Error(err)
					}
				}
			})
		})
	}
}

func TestDedupeDuplicates(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "nuclei")
	require.Nil(t, err, "could not create temporary storage")
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	storage, err := New(tempDir)
	require.Nil(t, err, "could not create duplicate storage")
	defer storage.Close()

	tests := []*output.ResultEvent{
		{TemplateID: "test", Host: "https://example.com"},
		{TemplateID: "test", Host: "https://example.com"},
	}
	first, err := storage.Index(tests[0])
	require.Nil(t, err, "could not index item")
	require.True(t, first, "could not index valid item")

	second, err := storage.Index(tests[1])
	require.Nil(t, err, "could not index item")
	require.False(t, second, "could index duplicate item")
}
