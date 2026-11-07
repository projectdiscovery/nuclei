package httputil

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

type cookieFieldsContextKey struct{}

// CookieURL matches the cookie scope used by net/http, including Host overrides.
func CookieURL(req *http.Request) *url.URL {
	if req.URL == nil || req.Host == "" {
		return req.URL
	}
	cloned := *req.URL
	cloned.Host = req.Host
	return &cloned
}

// SetCookieFields records the raw fields produced by cookie fuzzing. Field
// boundaries cannot be recovered from payloads containing unmatched quotes.
func SetCookieFields(req *http.Request, fields []string) {
	fields = append([]string(nil), fields...)
	*req = *req.WithContext(context.WithValue(req.Context(), cookieFieldsContextKey{}, fields))
}

// CookieFields returns a copy of the structured fields recorded by cookie fuzzing.
func CookieFields(req *http.Request) []string {
	fields, _ := req.Context().Value(cookieFieldsContextKey{}).([]string)
	return append([]string(nil), fields...)
}

// SplitCookieHeader separates cookie pairs without changing their raw bytes.
// Quoted semicolons can be intentional fuzzing payloads. An unmatched quote
// keeps the rest of the header in the same value rather than inventing pairs.
func SplitCookieHeader(header string) []string {
	parts := make([]string, 0, strings.Count(header, ";")+1)
	start := 0
	quoted := false
	for i := 0; i < len(header); i++ {
		if quoted && header[i] == '\\' {
			i++ // Preserve an escaped quote without ending the quoted value.
			continue
		}
		switch header[i] {
		case '"':
			quoted = !quoted
		case ';':
			if !quoted {
				parts = append(parts, header[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, header[start:])
}
