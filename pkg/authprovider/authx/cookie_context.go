package authx

import (
	"context"
	"net/http"
	"strings"

	httputil "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils/http"
)

type cookieAuthContextKey struct{}

// IsAuthCookie reports whether an auth strategy installed the named cookie.
// HTTP cookie reuse must preserve these explicit credentials over jar values.
func IsAuthCookie(ctx context.Context, name string) bool {
	names, _ := ctx.Value(cookieAuthContextKey{}).(map[string]struct{})
	_, ok := names[name]
	return ok
}

func markCookieAuth(req *http.Request, names []string) {
	if len(names) == 0 {
		return
	}
	existing, _ := req.Context().Value(cookieAuthContextKey{}).(map[string]struct{})
	// Contexts can be shared by clones and redirects. Publish a new set rather
	// than modifying the names recorded by an earlier strategy.
	protected := make(map[string]struct{}, len(existing)+len(names))
	// A Header strategy can replace the entire Cookie header. Keep earlier
	// ownership only for cookie names still present in the request.
	for _, header := range req.Header.Values("Cookie") {
		for _, part := range httputil.SplitCookieHeader(header) {
			name, _, _ := strings.Cut(part, "=")
			name = strings.TrimSpace(name)
			if _, ok := existing[name]; ok {
				protected[name] = struct{}{}
			}
		}
	}
	for _, name := range names {
		protected[name] = struct{}{}
	}
	*req = *req.WithContext(context.WithValue(req.Context(), cookieAuthContextKey{}, protected))
}
