package replacer

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/marker"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Replace substitutes each {{key}} and §key§ placeholder in template whose key
// is in values, scanning template once from left to right.
//
// Values are data: Replace never scans an inserted value for placeholders, so
// a value cannot pull in another value, alone or together with the template
// text around it. Text that does not form a known placeholder is kept as is.
func Replace(template string, values map[string]interface{}) string {
	if len(values) == 0 {
		return template
	}

	scan := newScanner(template, values)

	start := scan.nextPlaceholder(0)
	if start < 0 {
		return template
	}

	var builder strings.Builder

	builder.Grow(len(template))

	written := 0 // template[:written] is already in builder

	for pos := start; pos >= 0; {
		value, end, ok := scan.resolve(pos)
		if !ok {
			// Not a known placeholder: keep it as text and look again one
			// byte later, so a placeholder nested in it still resolves.
			pos = scan.nextPlaceholder(pos + 1)

			continue
		}

		builder.WriteString(template[written:pos])
		builder.WriteString(value)

		written = end
		pos = scan.nextPlaceholder(end)
	}

	builder.WriteString(template[written:])

	return builder.String()
}

// directLookupLimit is the longest candidate key that resolve looks up in
// values without first comparing it to the longest key there.
const directLookupLimit = 32

// scanner finds the placeholders of one template. Replace asks for positions
// that never decrease, so each finder searches every byte at most once. A
// candidate key longer than every key in values is rejected without hashing
// it. Together, these keep Replace linear in the template length.
type scanner struct {
	template                  string
	values                    map[string]any
	longestKey                int // length of the longest key in values; -1 until needed
	braceOpen, braceClose     finder
	generalOpen, generalClose finder
}

func newScanner(template string, values map[string]any) scanner {
	return scanner{
		template:     template,
		values:       values,
		longestKey:   -1,
		braceOpen:    newFinder(marker.ParenthesisOpen),
		braceClose:   newFinder(marker.ParenthesisClose),
		generalOpen:  newFinder(marker.General),
		generalClose: newFinder(marker.General),
	}
}

// nextPlaceholder returns the index of the next {{ or § at or after from that
// can still be closed, or -1 when there is none. Once no closing marker of a
// kind is left, no later opening marker of that kind can close.
func (s *scanner) nextPlaceholder(from int) int {
	brace, general := -1, -1

	if !s.braceClose.exhausted() {
		brace = s.braceOpen.index(s.template, from)
	}

	if !s.generalClose.exhausted() {
		general = s.generalOpen.index(s.template, from)
	}

	if brace < 0 || (general >= 0 && general < brace) {
		return general
	}

	return brace
}

// resolve returns the value of the placeholder that starts at index start,
// and the index just past it, when its key is in values.
func (s *scanner) resolve(start int) (string, int, bool) {
	open, closing := marker.ParenthesisOpen, &s.braceClose
	if strings.HasPrefix(s.template[start:], marker.General) {
		open, closing = marker.General, &s.generalClose
	}

	keyStart := start + len(open)

	keyEnd := closing.index(s.template, keyStart)
	if keyEnd < 0 {
		return "", 0, false
	}

	key := s.template[keyStart:keyEnd]
	if len(key) > directLookupLimit && len(key) > s.longestKeyLen() {
		return "", 0, false
	}

	value, ok := s.values[key]
	if !ok {
		return "", 0, false
	}

	return types.ToString(value), keyEnd + len(closing.needle), true
}

// longestKeyLen returns the length of the longest key in values.
func (s *scanner) longestKeyLen() int {
	if s.longestKey < 0 {
		s.longestKey = 0
		for key := range s.values {
			s.longestKey = max(s.longestKey, len(key))
		}
	}

	return s.longestKey
}

// finder finds one marker in a template. Its callers pass positions that
// never decrease, so it keeps the last match until the scan passes it, and a
// failed search answers every later call.
type finder struct {
	needle   string
	next     int // last match, or -1 when none is left
	searched bool
}

func newFinder(needle string) finder {
	return finder{needle: needle, next: -1, searched: false}
}

// index returns the index of the first needle at or after from, or -1.
func (f *finder) index(template string, from int) int {
	if f.searched && (f.next < 0 || f.next >= from) {
		return f.next
	}

	f.searched = true

	f.next = strings.Index(template[from:], f.needle)
	if f.next >= 0 {
		f.next += from
	}

	return f.next
}

// exhausted reports whether a search found no match left in the template.
func (f *finder) exhausted() bool {
	return f.searched && f.next < 0
}

// ReplaceOne replaces the first {{key}} and the first §key§ in template with
// value.
//
// Deprecated: ReplaceOne finds the placeholder by searching template, so when
// template already holds substituted values it can replace text that a value
// introduced instead of the placeholder the caller meant. Render by position
// with Replace instead.
func ReplaceOne(template string, key string, value interface{}) string {
	data := replaceOneWithMarkers(template, key, value, marker.ParenthesisOpen, marker.ParenthesisClose)
	return replaceOneWithMarkers(data, key, value, marker.General, marker.General)
}

// replaceOneWithMarkers is a helper function that perform one time replacement
func replaceOneWithMarkers(template, key string, value interface{}, openMarker, closeMarker string) string {
	return strings.Replace(template, openMarker+key+closeMarker, types.ToString(value), 1)
}
