package xsscontext

import (
	"regexp"
)

type XSSContext string

const (
	ContextHTML      XSSContext = "html"
	ContextAttribute XSSContext = "attribute"
	ContextJS        XSSContext = "javascript"
	ContextURL       XSSContext = "url"
	ContextUnknown   XSSContext = "unknown"
)

func detectContext(body string, marker string) XSSContext {
	if marker == "" || body == "" {
		return ContextUnknown
	}

	// Order matters (more specific → less specific)
	jsRe := regexp.MustCompile(`(?is)<script[^>]*>.*?` + regexp.QuoteMeta(marker))
	if jsRe.MatchString(body) {
		return ContextJS
	}

	urlRe := regexp.MustCompile(`(?is)\bhref\s*=\s*["'][^"']*` + regexp.QuoteMeta(marker))
	if urlRe.MatchString(body) {
		return ContextURL
	}

	attrRe := regexp.MustCompile(`(?is)\b\w[\w:-]*\s*=\s*["'][^"']*` + regexp.QuoteMeta(marker))
	if attrRe.MatchString(body) {
		return ContextAttribute
	}

	htmlRe := regexp.MustCompile(`(?is)>[^<]*` + regexp.QuoteMeta(marker) + `[^<]*<`)
	if htmlRe.MatchString(body) {
		return ContextHTML
	}

	// Fallback: if it’s reflected but we can’t classify
	if regexp.MustCompile(regexp.QuoteMeta(marker)).MatchString(body) {
		return ContextUnknown
	}

	return ContextUnknown
}

