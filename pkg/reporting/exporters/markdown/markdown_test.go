package markdown

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSanitizeFilenameStripsPathSeparatorsAndDotDot ensures user-supplied
// values (event.Host, event.TemplateID) used to build subdirectory and file
// names cannot escape the reporting directory.
//
// The previous sanitizer only replaced "/" but not "\\" and not "..", which
// allowed Windows-style traversal like "..\\..\\foo" to flow through to
// filepath.Join + filepath.Clean and end up outside the configured directory.
func TestSanitizeFilenameStripsPathSeparatorsAndDotDot(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		mustNot  []string
		mustHave []string
	}{
		{
			name:    "forward slash traversal",
			input:   "../../etc/passwd",
			mustNot: []string{"/", ".."},
		},
		{
			name:    "backslash traversal",
			input:   "..\\..\\etc\\passwd",
			mustNot: []string{"\\", ".."},
		},
		{
			name:    "mixed separators",
			input:   "..\\../etc",
			mustNot: []string{"/", "\\", ".."},
		},
		{
			name:    "bare dotdot",
			input:   "..",
			mustNot: []string{".."},
		},
		{
			name:     "embedded dotdot stays substringless",
			input:    "evil..foo",
			mustNot:  []string{".."},
			mustHave: []string{"evil"},
		},
		{
			name:     "legitimate hostname is preserved enough",
			input:    "example.com",
			mustHave: []string{"example", "com"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := sanitizeFilename(tc.input)
			for _, s := range tc.mustNot {
				require.False(t, strings.Contains(out, s),
					"sanitized %q (in=%q) must not contain %q", out, tc.input, s)
			}
			for _, s := range tc.mustHave {
				require.True(t, strings.Contains(out, s),
					"sanitized %q (in=%q) should still contain %q", out, tc.input, s)
			}
		})
	}
}

// TestSanitizedSubdirectoryStaysWithinReportDirectory is a stronger assertion
// that the sanitizer's output, when joined into the report directory and
// cleaned by filepath.Clean (the same code path the markdown exporter walks),
// never escapes that directory. This guards against future regressions in the
// sanitizer that might let a separator slip through.
func TestSanitizedSubdirectoryStaysWithinReportDirectory(t *testing.T) {
	reportDir := t.TempDir()
	hostileInputs := []string{
		"../../etc/passwd",
		"..\\..\\etc\\passwd",
		"..",
		"..\\..\\..\\Windows\\System32",
		"some/host/../../escape",
		// Many-dot variants that earlier ReplaceAll iterations might leave a
		// stray ".." behind (strings.ReplaceAll guarantees no remaining match
		// of the pattern, so even adversarial dot runs collapse safely).
		"...",
		"....",
		".....",
		"......",
		"./.../...",
		"/../../foo",
		"\\..\\..\\foo",
		// Mixed separators on Linux/Windows.
		"a/b\\..\\..\\..\\c",
		"a\\b/../../../c",
		// Embedded NUL — written here as escape; the sanitizer doesn't
		// special-case it, but filepath.Clean handles it as a literal byte.
		"foo\x00..\\bar",
		// Long traversal sequences that cross MAX_PATH-ish boundaries.
		strings.Repeat("../", 200) + "etc/passwd",
		strings.Repeat("..\\", 200) + "Windows",
	}

	for _, in := range hostileInputs {
		t.Run(in, func(t *testing.T) {
			subdir := sanitizeFilename(in)
			// After sanitize the result must not contain a path separator or
			// a parent-reference token at all; otherwise filepath.Clean +
			// filepath.Join could collapse it into a traversal.
			require.False(t, strings.ContainsAny(subdir, "/\\"),
				"sanitizer leaked a path separator: in=%q out=%q", in, subdir)
			require.False(t, strings.Contains(subdir, ".."),
				"sanitizer leaked '..' substring: in=%q out=%q", in, subdir)

			joined := filepath.Clean(filepath.Join(reportDir, subdir))

			// Cleaned path must remain a child of reportDir (or equal to it
			// when the sanitizer reduced everything to underscores).
			rel, err := filepath.Rel(reportDir, joined)
			require.NoError(t, err)
			require.NotEqual(t, "..", rel)
			require.False(t, strings.HasPrefix(rel, ".."+string(filepath.Separator)),
				"input %q produced rel %q which escapes reportDir", in, rel)
		})
	}
}

// FuzzSanitizeFilenameStaysContained is a property test: for any input the
// sanitizer can be fed (event.Host, event.TemplateID, etc.), the output joined
// to a fixed report directory must always resolve back inside that directory.
// This is the reporter's invariant, and the fuzz test makes future regressions
// in the sanitizer impossible to land silently.
func FuzzSanitizeFilenameStaysContained(f *testing.F) {
	seeds := []string{
		"",
		"foo",
		"..",
		"../..",
		"/../etc/passwd",
		"\\..\\..\\Windows",
		"..\\../mixed",
		"foo..bar..baz",
		strings.Repeat("..", 100),
		strings.Repeat("..\\", 100),
		strings.Repeat("../", 100),
		strings.Repeat(".", 1000),
		strings.Repeat("\\", 1000),
		strings.Repeat("/", 1000),
		"\x00\x00\x00..",
		"foo\x00..\\bar",
		"\u202e..\u202d", // RTL/LTR marks around dotdot
	}
	for _, s := range seeds {
		f.Add(s)
	}

	reportDir := f.TempDir()

	f.Fuzz(func(t *testing.T, in string) {
		out := sanitizeFilename(in)
		// Sanitize must never emit a separator or "..". This is the invariant
		// the markdown exporter relies on at filepath.Join time.
		if strings.ContainsAny(out, "/\\") {
			t.Fatalf("sanitizer leaked a separator: in=%q out=%q", in, out)
		}
		if strings.Contains(out, "..") {
			t.Fatalf("sanitizer leaked '..': in=%q out=%q", in, out)
		}

		// The joined+cleaned path must stay inside the report dir.
		joined := filepath.Clean(filepath.Join(reportDir, out))
		rel, err := filepath.Rel(reportDir, joined)
		if err != nil {
			t.Fatalf("Rel error for in=%q out=%q: %v", in, out, err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("escape from reportDir: in=%q out=%q rel=%q", in, out, rel)
		}
	})
}
