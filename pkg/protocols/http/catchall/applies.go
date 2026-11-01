package catchall

import (
	"slices"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
)

// hostWideTags mark templates whose claim is about the host rather than the
// requested path. A single page app serves its shell, title and scripts on
// every path, so "this is Grafana" stays true on its catch-all page.
var hostWideTags = []string{"tech", "panel"}

// evidenceOutsideBody lists the response parts a catch-all page does not
// disprove: headers are usually set for the whole host, and an out-of-band
// interaction proves the request reached something regardless of the page.
var evidenceOutsideBody = []string{"header", "interactsh"}

// Applies reports whether a match by a template with info and ops can be
// discounted when the response is the host's catch-all page.
func Applies(info model.Info, ops *operators.Operators) bool {
	if ops == nil {
		return false
	}
	if slices.ContainsFunc(info.Tags.ToSlice(), func(tag string) bool { return slices.Contains(hostWideTags, tag) }) {
		return false
	}
	for _, matcher := range ops.Matchers {
		if readsOutsideBody(matcher.Part) || slices.ContainsFunc(matcher.DSL, readsOutsideBody) {
			return false
		}
	}
	return true
}

func readsOutsideBody(s string) bool {
	s = strings.ToLower(s)
	return slices.ContainsFunc(evidenceOutsideBody, func(part string) bool { return strings.Contains(s, part) })
}
