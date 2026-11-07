// Package normalize collapses URLs that address the same resource onto one
// form, so a target list built by a crawler does not run every template several
// times over for what is effectively the same target.
//
// Only differences that cannot change the response are removed: host case, the
// fragment (never sent to the server), a default port, a trailing slash, and
// well known tracking parameters. Path case is left alone, because paths are
// case sensitive on most servers.
package normalize

import (
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"
)

// trackingParams are query keys added by ad and analytics platforms. They are
// echoed back at most and never select a different resource, so two URLs that
// differ only by these are the same target. The list is deliberately limited to
// vendor prefixed names: a generic key like "ref" or "id" can be functional.
var trackingParams = map[string]struct{}{
	"utm_source":   {},
	"utm_medium":   {},
	"utm_campaign": {},
	"utm_term":     {},
	"utm_content":  {},
	"utm_id":       {},
	"utm_reader":   {},
	"utm_name":     {},
	"gclid":        {},
	"gbraid":       {},
	"wbraid":       {},
	"dclid":        {},
	"fbclid":       {},
	"msclkid":      {},
	"mc_cid":       {},
	"mc_eid":       {},
	"igshid":       {},
	"twclid":       {},
	"ttclid":       {},
	"yclid":        {},
	"_ga":          {},
	"_gl":          {},
}

// IsTrackingParam reports whether a query key is a known tracking parameter.
func IsTrackingParam(key string) bool {
	_, ok := trackingParams[strings.ToLower(key)]
	return ok
}

// URL returns the canonical form of raw. A value that cannot be parsed, or that
// carries no host, is returned unchanged: the input provider accepts things
// that are not URLs at all, and guessing at those would lose targets.
func URL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return raw
	}

	// The scheme is case insensitive per RFC 3986, but the parser rejects one
	// that is not lowercase, so fold it before handing the value over.
	if idx := strings.Index(trimmed, "://"); idx > 0 {
		trimmed = strings.ToLower(trimmed[:idx]) + trimmed[idx:]
	}

	parsed, err := urlutil.Parse(trimmed)
	if err != nil || parsed == nil || parsed.Host == "" {
		return raw
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Fragment = ""

	if host, port, ok := splitHostPort(parsed.Host); ok && isDefaultPort(parsed.Scheme, port) {
		parsed.Host = host
	}

	stripTrackingParams(parsed)

	// A trailing slash addresses the same resource as its absence for every
	// path but the root, where "/" is the path.
	if path := parsed.Path; len(path) > 1 && strings.HasSuffix(path, "/") {
		parsed.Path = strings.TrimRight(path, "/")
	}

	return parsed.String()
}

// stripTrackingParams removes known tracking keys, leaving every other
// parameter and its value untouched.
func stripTrackingParams(parsed *urlutil.URL) {
	if parsed.Params == nil || parsed.Params.IsEmpty() {
		return
	}
	// collected first: deleting while iterating would mutate the order under us
	var drop []string
	parsed.Params.Iterate(func(key string, _ []string) bool {
		if IsTrackingParam(key) {
			drop = append(drop, key)
		}
		return true
	})
	for _, key := range drop {
		parsed.Params.Del(key)
	}
	parsed.Update()
}

// splitHostPort separates a host and port, tolerating bracketed IPv6 literals.
func splitHostPort(host string) (string, string, bool) {
	if strings.HasPrefix(host, "[") {
		end := strings.LastIndex(host, "]")
		if end < 0 {
			return host, "", false
		}
		rest := host[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return host, "", false
		}
		return host[:end+1], rest[1:], true
	}
	idx := strings.LastIndex(host, ":")
	if idx < 0 {
		return host, "", false
	}
	return host[:idx], host[idx+1:], true
}

func isDefaultPort(scheme, port string) bool {
	return (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
}

// Origin returns the scheme and host a URL addresses, which is what a template
// built only from {{RootURL}} resolves against. It returns "" when the value
// carries no host, so callers can fall back to treating the target as unique.
func Origin(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if idx := strings.Index(trimmed, "://"); idx > 0 {
		trimmed = strings.ToLower(trimmed[:idx]) + trimmed[idx:]
	}
	parsed, err := urlutil.Parse(trimmed)
	if err != nil || parsed == nil || parsed.Host == "" {
		return ""
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Host)
	if h, port, ok := splitHostPort(host); ok && isDefaultPort(scheme, port) {
		host = h
	}
	if scheme == "" {
		return host
	}
	return scheme + "://" + host
}
