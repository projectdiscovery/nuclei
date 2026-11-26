package interactsh

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	serverint "github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

const feedTestID = "c0ffee00c0ffee00c0ff"

func newFeedFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "feed.jsonl")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	return path
}

func appendFeed(t *testing.T, path string, text string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = file.WriteString(text)
	require.NoError(t, err)
	require.NoError(t, file.Close())
}

func feedLine(t *testing.T, interaction serverint.Interaction) string {
	t.Helper()
	data, err := json.Marshal(interaction)
	require.NoError(t, err)
	return string(data) + "\n"
}

type collected struct {
	mu   sync.Mutex
	hits []*serverint.Interaction
}

func (c *collected) add(i *serverint.Interaction) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hits = append(c.hits, i)
}

func (c *collected) ids() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := make([]string, 0, len(c.hits))
	for _, hit := range c.hits {
		ids = append(ids, hit.UniqueID)
	}
	return ids
}

func TestFeedURLsUseTheOwnersRegistration(t *testing.T) {
	feed, err := newFeedSource(newFeedFile(t), feedTestID, "OOB.Example.")
	require.NoError(t, err)

	first, second := feed.URL(), feed.URL()
	require.NotEqual(t, first, second)
	label, domain, ok := strings.Cut(first, ".")
	require.True(t, ok)
	require.Equal(t, "oob.example", domain)
	require.True(t, strings.HasPrefix(label, feedTestID), label)
	nonce := strings.TrimPrefix(label, feedTestID)
	require.Len(t, nonce, 13)
	for _, r := range nonce {
		require.Contains(t, nonceAlphabet, string(r))
	}

	require.NoError(t, feed.Close())
	require.Empty(t, feed.URL(), "a closed feed issues no URLs")
}

func TestFeedNeedsAnExistingFile(t *testing.T) {
	_, err := newFeedSource(filepath.Join(t.TempDir(), "missing.jsonl"), feedTestID, "oob.example")
	require.Error(t, err)
}

func TestFeedReadsCompleteLinesOfItsRegistration(t *testing.T) {
	path := newFeedFile(t)
	feed, err := newFeedSource(path, feedTestID, "oob.example")
	require.NoError(t, err)
	got := &collected{}

	mine := feedLine(t, serverint.Interaction{Protocol: "dns", UniqueID: feedTestID + "AAAAAAAAAAAAA"})
	other := feedLine(t, serverint.Interaction{Protocol: "http", UniqueID: "ffffffffffffffffffffbbbbbbbbbbbbb"})
	appendFeed(t, path, other+"not json\n\n"+mine[:20])
	require.NoError(t, feed.read(got.add))
	require.Empty(t, got.ids(), "other registrations, garbage and a half-written line are skipped")

	appendFeed(t, path, mine[20:])
	require.NoError(t, feed.read(got.add))
	require.Equal(t, []string{feedTestID + "aaaaaaaaaaaaa"}, got.ids(), "the finished line is read once, id lowercased")

	require.NoError(t, feed.read(got.add))
	require.Len(t, got.ids(), 1, "nothing new, nothing passed on")
}

// TestFeedReadStopsAtTheSizeItStartedWith checks that a feed the owner keeps
// appending to while it is read does not keep one read going forever.
func TestFeedReadStopsAtTheSizeItStartedWith(t *testing.T) {
	path := newFeedFile(t)
	feed, err := newFeedSource(path, feedTestID, "oob.example")
	require.NoError(t, err)
	line := feedLine(t, serverint.Interaction{Protocol: "dns", UniqueID: feedTestID + "aaaaaaaaaaaaa"})
	appendFeed(t, path, line)

	got := &collected{}
	appendEach := func(i *serverint.Interaction) {
		got.add(i)
		appendFeed(t, path, line)
	}
	require.NoError(t, feed.read(appendEach))
	require.Len(t, got.ids(), 1, "the line appended during the read waits for the next one")

	require.NoError(t, feed.read(got.add))
	require.Len(t, got.ids(), 2)
}

func TestFeedSkipsIDsWithAMalformedNonce(t *testing.T) {
	path := newFeedFile(t)
	feed, err := newFeedSource(path, feedTestID, "oob.example")
	require.NoError(t, err)
	got := &collected{}

	for _, id := range []string{
		feedTestID + "bbbb",           // nonce too short
		feedTestID + "bbbbbbbbbbbbbb", // nonce too long
		feedTestID + "lllllllllllll",  // l is outside z-base-32
		feedTestID + "bbbbbbbbbbbb.",  // so is a dot
		"",
	} {
		appendFeed(t, path, feedLine(t, serverint.Interaction{Protocol: "dns", UniqueID: id}))
	}
	require.NoError(t, feed.read(got.add))
	require.Empty(t, got.ids())
}

// Lines longer than the 32 KiB read buffer arrive in several chunks, within
// one read or across reads, and are passed on whole.
func TestFeedReadsLinesLongerThanTheReadBuffer(t *testing.T) {
	path := newFeedFile(t)
	feed, err := newFeedSource(path, feedTestID, "oob.example")
	require.NoError(t, err)
	got := &collected{}

	raw := strings.Repeat("x", 100*1024)
	line := feedLine(t, serverint.Interaction{Protocol: "http", UniqueID: feedTestID + "bbbbbbbbbbbbb", RawRequest: raw})
	appendFeed(t, path, line)
	require.NoError(t, feed.read(got.add))

	line = feedLine(t, serverint.Interaction{Protocol: "http", UniqueID: feedTestID + "ccccccccccccc", RawRequest: raw})
	appendFeed(t, path, line[:70*1024])
	require.NoError(t, feed.read(got.add))
	require.Len(t, got.ids(), 1, "the second line is not finished yet")
	appendFeed(t, path, line[70*1024:])
	require.NoError(t, feed.read(got.add))

	require.Equal(t, []string{feedTestID + "bbbbbbbbbbbbb", feedTestID + "ccccccccccccc"}, got.ids())
	for _, hit := range got.hits {
		require.Equal(t, raw, hit.RawRequest)
	}
}

// A line over maxFeedLine is dropped whether it completes within one read or
// is still unfinished when it crosses the limit, and the lines after it are read.
func TestFeedDropsLinesOverTheLimit(t *testing.T) {
	bigLine := func(extra int) string {
		return feedLine(t, serverint.Interaction{Protocol: "http", UniqueID: feedTestID + "bbbbbbbbbbbbb", RawRequest: strings.Repeat("x", maxFeedLine+extra)})
	}
	big := bigLine(0)
	require.Greater(t, len(big), maxFeedLine+1)
	next := feedLine(t, serverint.Interaction{Protocol: "dns", UniqueID: feedTestID + "ccccccccccccc"})

	for name, line := range map[string]string{
		// Ends in the chunk after the one that reaches the limit.
		"complete just over the limit": big,
		// Crosses the limit chunks before its end, which are skipped.
		"complete far over the limit": bigLine(100 * 1024),
	} {
		t.Run(name, func(t *testing.T) {
			path := newFeedFile(t)
			feed, err := newFeedSource(path, feedTestID, "oob.example")
			require.NoError(t, err)
			got := &collected{}

			appendFeed(t, path, line+next)
			require.NoError(t, feed.read(got.add))
			require.Equal(t, []string{feedTestID + "ccccccccccccc"}, got.ids())
		})
	}

	t.Run("unfinished", func(t *testing.T) {
		path := newFeedFile(t)
		feed, err := newFeedSource(path, feedTestID, "oob.example")
		require.NoError(t, err)
		got := &collected{}

		appendFeed(t, path, big[:maxFeedLine+10])
		require.NoError(t, feed.read(got.add))
		require.True(t, feed.discarding)
		require.Empty(t, feed.partial, "the unfinished line is not kept")

		appendFeed(t, path, big[maxFeedLine+10:]+next)
		require.NoError(t, feed.read(got.add))
		require.False(t, feed.discarding)
		require.Equal(t, []string{feedTestID + "ccccccccccccc"}, got.ids())
	})
}

func TestFeedStartsOverWhenTheFileShrinks(t *testing.T) {
	path := newFeedFile(t)
	feed, err := newFeedSource(path, feedTestID, "oob.example")
	require.NoError(t, err)
	got := &collected{}

	appendFeed(t, path, feedLine(t, serverint.Interaction{Protocol: "dns", UniqueID: feedTestID + "bbbbbbbbbbbbb", RawRequest: strings.Repeat("x", 200)}))
	require.NoError(t, feed.read(got.add))
	require.NoError(t, os.WriteFile(path, []byte(feedLine(t, serverint.Interaction{Protocol: "dns", UniqueID: feedTestID + "ccccccccccccc"})), 0o600))
	require.NoError(t, feed.read(got.add))
	require.Equal(t, []string{feedTestID + "bbbbbbbbbbbbb", feedTestID + "ccccccccccccc"}, got.ids())
}

func TestFeedStartsOverWhenTheFileIsReplaced(t *testing.T) {
	path := newFeedFile(t)
	feed, err := newFeedSource(path, feedTestID, "oob.example")
	require.NoError(t, err)
	got := &collected{}

	appendFeed(t, path, feedLine(t, serverint.Interaction{UniqueID: feedTestID + "bbbbbbbbbbbbb"}))
	require.NoError(t, feed.read(got.add))

	replacement := filepath.Join(t.TempDir(), "replacement.jsonl")
	require.NoError(t, os.WriteFile(replacement, []byte(feedLine(t, serverint.Interaction{UniqueID: feedTestID + "ccccccccccccc"})), 0o600))
	require.NoError(t, os.Rename(replacement, path))
	require.NoError(t, feed.read(got.add))
	require.Equal(t, []string{feedTestID + "bbbbbbbbbbbbb", feedTestID + "ccccccccccccc"}, got.ids())
}

// Truncated in place and refilled to where it was read up to between two
// reads: same inode, same size, other lines.
func TestFeedStartsOverWhenTheFileIsRewrittenInPlace(t *testing.T) {
	path := newFeedFile(t)
	feed, err := newFeedSource(path, feedTestID, "oob.example")
	require.NoError(t, err)
	got := &collected{}

	first := feedLine(t, serverint.Interaction{UniqueID: feedTestID + "bbbbbbbbbbbbb", Timestamp: time.Unix(1, 0).UTC()})
	appendFeed(t, path, first)
	require.NoError(t, feed.read(got.add))

	second := feedLine(t, serverint.Interaction{UniqueID: feedTestID + "ccccccccccccc", Timestamp: time.Unix(2, 0).UTC()})
	require.Len(t, second, len(first))
	require.NoError(t, os.WriteFile(path, []byte(second), 0o600)) // O_TRUNC keeps the inode
	require.NoError(t, feed.read(got.add))
	require.Equal(t, []string{feedTestID + "bbbbbbbbbbbbb", feedTestID + "ccccccccccccc"}, got.ids())
}

// A feed that goes missing mid-scan is reported and read again from the start
// once its owner recreates it.
func TestFeedRecoversWhenTheFileReappears(t *testing.T) {
	path := newFeedFile(t)
	feed, err := newFeedSource(path, feedTestID, "oob.example")
	require.NoError(t, err)
	got := &collected{}

	appendFeed(t, path, feedLine(t, serverint.Interaction{UniqueID: feedTestID + "bbbbbbbbbbbbb"}))
	require.NoError(t, feed.read(got.add))

	require.NoError(t, os.Remove(path))
	require.Error(t, feed.read(got.add))
	feed.readLogged(got.add) // logs instead of failing the poll loop

	require.NoError(t, os.WriteFile(path, []byte(feedLine(t, serverint.Interaction{UniqueID: feedTestID + "ccccccccccccc"})), 0o600))
	require.NoError(t, feed.read(got.add))
	require.Equal(t, []string{feedTestID + "bbbbbbbbbbbbb", feedTestID + "ccccccccccccc"}, got.ids())
}

func TestFeedStartPollingRejectsBadArguments(t *testing.T) {
	feed, err := newFeedSource(newFeedFile(t), feedTestID, "oob.example")
	require.NoError(t, err)
	require.Error(t, feed.StartPolling(0, func(*serverint.Interaction) {}))
	require.Error(t, feed.StartPolling(time.Second, nil))
	require.Error(t, feed.StopPolling(), "rejected starts leave the feed idle")
}

func TestFeedStopPollingReadsWhatArrivedLast(t *testing.T) {
	path := newFeedFile(t)
	feed, err := newFeedSource(path, feedTestID, "oob.example")
	require.NoError(t, err)
	got := &collected{}

	require.NoError(t, feed.StartPolling(time.Hour, got.add))
	require.Error(t, feed.StartPolling(time.Hour, got.add), "already polling")
	require.Error(t, feed.Close(), "must stop polling first")

	appendFeed(t, path, feedLine(t, serverint.Interaction{Protocol: "http", UniqueID: feedTestID + "bbbbbbbbbbbbb"}))
	require.NoError(t, feed.StopPolling())
	require.Equal(t, []string{feedTestID + "bbbbbbbbbbbbb"}, got.ids())

	require.Error(t, feed.StopPolling(), "not polling")
	require.NoError(t, feed.Close())
	require.Error(t, feed.Close(), "already closed")
	require.Error(t, feed.StartPolling(time.Hour, got.add), "closed")
}

func TestValidateFeedOptions(t *testing.T) {
	require.NoError(t, ValidateFeedOptions(feedTestID, "oob.example", "feed.jsonl"))
	require.Error(t, ValidateFeedOptions(feedTestID, "", "feed.jsonl"), "all three are needed")
	require.Error(t, ValidateFeedOptions("short", "oob.example", "feed.jsonl"))
	require.Error(t, ValidateFeedOptions("c0ffee00c0ffee00c0fw", "oob.example", "feed.jsonl"), "w is outside the id alphabet")
	require.Error(t, ValidateFeedOptions(feedTestID, "oob.example:8080", "feed.jsonl"), "no port")
	require.Error(t, ValidateFeedOptions(feedTestID, "https://oob.example", "feed.jsonl"), "no scheme")
	require.Error(t, ValidateFeedOptions(feedTestID, "oob..example", "feed.jsonl"), "repeated dots are invalid")
	require.Error(t, ValidateFeedOptions(feedTestID, ".", "feed.jsonl"), "root alone is no domain")
	require.Error(t, ValidateFeedOptions(feedTestID, "-oob.example", "feed.jsonl"), "no leading hyphen")
	require.Error(t, ValidateFeedOptions(feedTestID, "oob-.example", "feed.jsonl"), "no trailing hyphen")
	require.Error(t, ValidateFeedOptions(feedTestID, "oob_x.example", "feed.jsonl"), "no underscore")
	require.Error(t, ValidateFeedOptions(feedTestID, strings.Repeat("a", 64)+".example", "feed.jsonl"), "labels stop at 63")
	require.NoError(t, ValidateFeedOptions(feedTestID, strings.Repeat("a", 63)+".example", "feed.jsonl"))
	require.NoError(t, ValidateFeedOptions(strings.ToUpper(feedTestID), "OOB.Example.", "feed.jsonl"))
}

// A template's interaction URL comes from the feed registration and the
// interaction the owner writes for it produces the template's result.
func TestClientMatchesAnInteractionFromTheFeed(t *testing.T) {
	path := newFeedFile(t)
	baseWriter := &requestRoutingWriter{}
	options := DefaultOptions(baseWriter, nil, &requestRoutingProgress{})
	options.FeedPath = path
	options.CorrelationID = feedTestID
	options.Domain = "oob.example"
	options.PollDuration = 10 * time.Millisecond
	options.CooldownPeriod = 0
	client, err := New(options)
	require.NoError(t, err)

	url, err := client.URL()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(url, feedTestID), url)
	require.Equal(t, "oob.example", client.GetHostname())

	matcher := &matchers.Matcher{
		Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
		Part:  "interactsh_protocol",
		Words: []string{"dns"},
	}
	op := &operators.Operators{Matchers: []*matchers.Matcher{matcher}}
	require.NoError(t, op.Compile())
	client.RequestEvent([]string{url}, &RequestData{
		Event: &output.InternalWrappedEvent{InternalEvent: output.InternalEvent{
			templateIdAttribute: "feed-oob",
			"host":              "target.example",
		}},
		Operators: op,
		MatchFunc: func(event map[string]interface{}, _ *matchers.Matcher) (bool, []string) {
			return event["interactsh_protocol"] == "dns", []string{"dns"}
		},
		ExtractFunc: func(map[string]interface{}, *extractors.Extractor) map[string]struct{} { return nil },
		MakeResultFunc: func(*output.InternalWrappedEvent) []*output.ResultEvent {
			return []*output.ResultEvent{{TemplateID: "feed-oob", MatcherStatus: true}}
		},
	})

	label := strings.TrimSuffix(url, ".oob.example")
	appendFeed(t, path, feedLine(t, serverint.Interaction{
		Protocol:      "dns",
		UniqueID:      label,
		FullId:        label,
		RawRequest:    "dns request",
		RemoteAddress: "203.0.113.7",
		Timestamp:     time.Now(),
	}))
	require.Eventually(t, func() bool { return baseWriter.ResultCount() == 1 }, 5*time.Second, 10*time.Millisecond)
	require.True(t, client.Close())
}
