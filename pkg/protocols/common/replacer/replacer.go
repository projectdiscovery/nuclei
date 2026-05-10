package replacer

import (
	"io"
	"strings"

	"github.com/projectdiscovery/fasttemplate"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/marker"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Replace replaces placeholders in template with values on the fly.
//
// This avoids the previous behavior of eagerly stringifying every value in the
// map for each call (which allocated a copy of the map on every per-request
// evaluate path) and skips the second-pass `§§` substitution when the marker
// is not present in the input.
func Replace(template string, values map[string]interface{}) string {
	// Fast path: no placeholders at all (cheaper than fasttemplate's own check
	// because it avoids constructing the closure).
	hasParenOpen := strings.Contains(template, marker.ParenthesisOpen)
	hasGeneral := strings.Contains(template, marker.General)
	if !hasParenOpen && !hasGeneral {
		return template
	}

	tagFn := makeStdTagFunc(values, marker.ParenthesisOpen, marker.ParenthesisClose)
	if hasParenOpen {
		template = fasttemplate.ExecuteFuncString(template, marker.ParenthesisOpen, marker.ParenthesisClose, tagFn)
	}
	if hasGeneral {
		gtagFn := makeStdTagFunc(values, marker.General, marker.General)
		template = fasttemplate.ExecuteFuncString(template, marker.General, marker.General, gtagFn)
	}
	return template
}

// Replace replaces one placeholder in template with one value on the fly.
func ReplaceOne(template string, key string, value interface{}) string {
	data := replaceOneWithMarkers(template, key, value, marker.ParenthesisOpen, marker.ParenthesisClose)
	return replaceOneWithMarkers(data, key, value, marker.General, marker.General)
}

// replaceOneWithMarkers is a helper function that perform one time replacement
func replaceOneWithMarkers(template, key string, value interface{}, openMarker, closeMarker string) string {
	return strings.Replace(template, openMarker+key+closeMarker, types.ToString(value), 1)
}

// makeStdTagFunc returns a fasttemplate.TagFunc that lazily resolves tags
// against the supplied map and stringifies hits on demand. Unknown tags are
// re-emitted with their original markers, mirroring fasttemplate's
// keepUnknownTagFunc behavior. This avoids allocating an intermediate
// `map[string]interface{}` and avoids eagerly stringifying values that the
// template never references.
func makeStdTagFunc(values map[string]interface{}, startTag, endTag string) fasttemplate.TagFunc {
	return func(w io.Writer, tag string) (int, error) {
		// Honor fasttemplate's nested startTag handling: if the tag itself
		// contains another startTag (e.g. "foo{{bar"), emit the literal
		// "{{" + leading prefix and only resolve the trailing portion. This
		// matches keepUnknownTagFunc semantics so behavior is preserved.
		if i := strings.LastIndex(tag, startTag); i >= 0 {
			if _, err := io.WriteString(w, startTag); err != nil {
				return 0, err
			}
			if _, err := io.WriteString(w, tag[:i]); err != nil {
				return 0, err
			}
			tag = tag[i+len(startTag):]
		}
		v, ok := values[tag]
		if !ok {
			n, err := io.WriteString(w, startTag)
			if err != nil {
				return n, err
			}
			n2, err := io.WriteString(w, tag)
			n += n2
			if err != nil {
				return n, err
			}
			n3, err := io.WriteString(w, endTag)
			return n + n3, err
		}
		if v == nil {
			return 0, nil
		}
		switch value := v.(type) {
		case []byte:
			return w.Write(value)
		case string:
			return io.WriteString(w, value)
		case fasttemplate.TagFunc:
			return value(w, tag)
		default:
			return io.WriteString(w, types.ToString(v))
		}
	}
}
