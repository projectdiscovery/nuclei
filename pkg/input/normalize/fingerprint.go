package normalize

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	urlutil "github.com/projectdiscovery/utils/url"
)

// Placeholders a structurally variable path segment collapses to. They are
// spelled out rather than hashed so a skipped-target log reads plainly.
const (
	placeholderNum  = "{num}"
	placeholderUUID = "{uuid}"
	placeholderHash = "{hash}"
	placeholderDate = "{date}"
	placeholderVar  = "{var}"
)

var (
	numericSegment = regexp.MustCompile(`^\d+$`)
	uuidSegment    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hashSegment    = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	// a date split across path positions is already caught as numeric segments
	dateSegment = regexp.MustCompile(`^\d{4}-\d{2}(-\d{2})?$`)
)

// classifySegment replaces a path segment that identifies a particular record
// with a placeholder, leaving segments that name a route alone.
func classifySegment(segment string) string {
	switch {
	case segment == "":
		return segment
	case numericSegment.MatchString(segment):
		return placeholderNum
	case uuidSegment.MatchString(segment):
		return placeholderUUID
	case dateSegment.MatchString(segment):
		return placeholderDate
	case hashSegment.MatchString(segment):
		return placeholderHash
	}
	return segment
}

// DefaultCollapseAfter is how many distinct values a single path position may
// hold on one host before the position itself is treated as an identifier. It
// catches slugs and names, which no pattern can recognise by shape alone.
const DefaultCollapseAfter = 20

// Fingerprinter groups URLs by the shape of their path and query, so a crawl
// that produced ten thousand product pages is recognised as one pattern.
//
// It is stateful by design: whether a path position is an identifier depends on
// how many distinct values that position has taken on that host, which is only
// knowable across the whole input.
type Fingerprinter struct {
	// MaxPerPattern is how many targets to keep per pattern. Zero keeps every
	// target, which is the default: dropping one is a target never scanned.
	MaxPerPattern int
	// CollapseAfter is the distinct-value threshold for a path position.
	CollapseAfter int

	mu       sync.Mutex
	kept     map[string]int
	position map[string]map[string]struct{}
}

// NewFingerprinter returns a fingerprinter keeping at most maxPerPattern
// targets for each pattern. A maxPerPattern of zero disables grouping.
func NewFingerprinter(maxPerPattern int) *Fingerprinter {
	return &Fingerprinter{
		MaxPerPattern: maxPerPattern,
		CollapseAfter: DefaultCollapseAfter,
		kept:          make(map[string]int),
		position:      make(map[string]map[string]struct{}),
	}
}

// Enabled reports whether the fingerprinter drops anything.
func (f *Fingerprinter) Enabled() bool {
	return f != nil && f.MaxPerPattern > 0
}

// Accept reports whether a target should be scanned, recording it against its
// pattern. A value that is not a URL is always accepted: it has no path to
// group by, and guessing would lose targets.
func (f *Fingerprinter) Accept(rawURL string) bool {
	if !f.Enabled() {
		return true
	}
	pattern, ok := f.pattern(rawURL)
	if !ok {
		return true
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.kept[pattern] >= f.MaxPerPattern {
		return false
	}
	f.kept[pattern]++
	return true
}

// Pattern returns the structural fingerprint of a URL, for tests and logging.
func (f *Fingerprinter) Pattern(rawURL string) string {
	pattern, _ := f.pattern(rawURL)
	return pattern
}

func (f *Fingerprinter) pattern(rawURL string) (string, bool) {
	trimmed := strings.TrimSpace(rawURL)
	if idx := strings.Index(trimmed, "://"); idx > 0 {
		trimmed = strings.ToLower(trimmed[:idx]) + trimmed[idx:]
	}
	parsed, err := urlParse(trimmed)
	if err != nil || parsed == nil || parsed.Host == "" {
		return "", false
	}

	host := strings.ToLower(parsed.Host)
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	shaped := make([]string, 0, len(segments))
	for index, segment := range segments {
		parent := strings.Join(segments[:index], "/")
		shaped = append(shaped, f.shapeSegment(host, parent, index, segment))
	}

	var builder strings.Builder
	builder.WriteString(host)
	builder.WriteString("/")
	builder.WriteString(strings.Join(shaped, "/"))
	if keys := queryKeys(parsed); len(keys) > 0 {
		// names without values: two searches differ by what was searched for,
		// not by the shape of the request
		builder.WriteString("?")
		builder.WriteString(strings.Join(keys, "&"))
	}
	return builder.String(), true
}

// shapeSegment classifies a segment by shape, then by how many distinct values
// the same position has already taken under this parent path on this host.
// The parent is part of the key so a busy /blog/<slug> does not also collapse
// /admin/<name> just because both sit at the same index.
func (f *Fingerprinter) shapeSegment(host, parent string, index int, segment string) string {
	if shaped := classifySegment(segment); shaped != segment {
		return shaped
	}
	if f.CollapseAfter <= 0 || segment == "" {
		return segment
	}

	key := host + "\x00" + parent + "\x00" + itoa(index)
	f.mu.Lock()
	values, ok := f.position[key]
	if !ok {
		values = make(map[string]struct{})
		f.position[key] = values
	}
	if len(values) < f.CollapseAfter {
		values[segment] = struct{}{}
	}
	collapsed := len(values) >= f.CollapseAfter
	f.mu.Unlock()

	if collapsed {
		return placeholderVar
	}
	return segment
}

// urlParse and queryKeys keep the url library dependency in one place.
func urlParse(raw string) (*urlutil.URL, error) {
	return urlutil.Parse(raw)
}

// queryKeys returns the query parameter names, sorted, with values dropped.
func queryKeys(parsed *urlutil.URL) []string {
	if parsed.Params == nil || parsed.Params.IsEmpty() {
		return nil
	}
	var keys []string
	parsed.Params.Iterate(func(key string, _ []string) bool {
		if !IsTrackingParam(key) {
			keys = append(keys, key)
		}
		return true
	})
	sort.Strings(keys)
	return keys
}

func itoa(value int) string { return strconv.Itoa(value) }
