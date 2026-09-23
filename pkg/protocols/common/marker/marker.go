package marker

import "strings"

const (
	// General marker (open/close)
	General = "§"
	// ParenthesisOpen marker - begin of a placeholder
	ParenthesisOpen = "{{"
	// ParenthesisClose marker - end of a placeholder
	ParenthesisClose = "}}"
)

const interactshURL = "interactsh-url"

// HasInteractshURLMarker returns true when data contains a complete Interactsh
// URL marker. It accepts raw markers ({{interactsh-url}}) and fully URL-encoded
// brace markers (%7B%7Binteractsh-url%7D%7D), but rejects mixed raw/encoded
// brace pairs.
func HasInteractshURLMarker(data string) bool {
	_, _, ok := NextInteractshURLMarker(data, 0)

	return ok
}

// FindInteractshURLMarkers returns complete Interactsh URL markers in data in
// left-to-right order.
func FindInteractshURLMarkers(data string) []string {
	var markers []string

	for start := 0; start < len(data); {
		markerStart, markerEnd, ok := NextInteractshURLMarker(data, start)
		if !ok {
			break
		}

		markers = append(markers, data[markerStart:markerEnd])
		start = markerEnd
	}

	return markers
}

// NextInteractshURLMarker returns the next complete Interactsh URL marker span
// at or after start.
func NextInteractshURLMarker(data string, start int) (int, int, bool) {
	if start < 0 {
		start = 0
	}

	for i := start; i < len(data); i++ {
		if strings.HasPrefix(data[i:], ParenthesisOpen) {
			if end, ok := matchInteractshURLMarker(data, i+len(ParenthesisOpen), hasRawClose); ok {
				return i, end, true
			}

			continue
		}

		if hasEncodedOpen(data, i) {
			if end, ok := matchInteractshURLMarker(data, i+len("%7B%7B"), hasEncodedClose); ok {
				return i, end, true
			}
		}
	}

	return 0, 0, false
}

func matchInteractshURLMarker(data string, bodyStart int, hasClose func(string, int) (int, bool)) (int, bool) {
	if !strings.HasPrefix(data[bodyStart:], interactshURL) {
		return 0, false
	}

	i := bodyStart + len(interactshURL)
	for suffixes := 0; suffixes < 3 && i < len(data) && data[i] == '_'; suffixes++ {
		next := i + 1
		if next >= len(data) || !isDigit(data[next]) {
			return 0, false
		}

		for next < len(data) && isDigit(data[next]) {
			next++
		}
		i = next
	}

	return hasClose(data, i)
}

func hasRawClose(data string, start int) (int, bool) {
	if strings.HasPrefix(data[start:], ParenthesisClose) {
		return start + len(ParenthesisClose), true
	}

	return 0, false
}

func hasEncodedOpen(data string, start int) bool {
	return hasEncodedBrace(data, start, 'B') && hasEncodedBrace(data, start+len("%7B"), 'B')
}

func hasEncodedClose(data string, start int) (int, bool) {
	if hasEncodedBrace(data, start, 'D') && hasEncodedBrace(data, start+len("%7D"), 'D') {
		return start + len("%7D%7D"), true
	}

	return 0, false
}

func hasEncodedBrace(data string, start int, brace byte) bool {
	if start+3 > len(data) || data[start] != '%' || data[start+1] != '7' {
		return false
	}

	got := data[start+2]

	return got == brace || got == brace+'a'-'A'
}

func isDigit(value byte) bool {
	return value >= '0' && value <= '9'
}
