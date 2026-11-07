package catchall

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

const spaShell = `<!doctype html><html><head><title>Acme Dashboard</title><script src="/static/js/main.4f2a9c.js"></script></head><body><noscript>You need to enable JavaScript to run this app.</noscript><div id="root"></div></body></html>`

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

// prober answers every probe with page and counts the probes.
func prober(page func(path string) Response) (Prober, *atomic.Int32) {
	var probes atomic.Int32
	return func(_ context.Context, path string) (Response, error) {
		probes.Add(1)
		return page(path), nil
	}, &probes
}

func TestSinglePageAppShellIsCatchAll(t *testing.T) {
	probe, _ := prober(func(string) Response { return Response{StatusCode: http.StatusOK, Body: spaShell} })
	d := New(0)

	got := d.Matches(context.Background(), mustURL(t, "http://acme.test/.env"), Response{StatusCode: http.StatusOK, Body: spaShell}, probe)
	require.True(t, got, "the shell served for a missing .env is not a finding")
}

func TestRealContentIsNotCatchAll(t *testing.T) {
	probe, _ := prober(func(string) Response { return Response{StatusCode: http.StatusOK, Body: spaShell} })
	d := New(0)

	env := Response{StatusCode: http.StatusOK, Body: "DB_HOST=db\nDB_PASSWORD=hunter2\nAPP_KEY=base64:abc"}
	require.False(t, d.Matches(context.Background(), mustURL(t, "http://acme.test/.env"), env, probe))
}

func TestHonestNotFoundIsNeverCatchAll(t *testing.T) {
	notFound := Response{StatusCode: http.StatusNotFound, Body: "<h1>404 Not Found</h1>"}
	probe, probes := prober(func(string) Response { return notFound })
	d := New(0)

	require.False(t, d.Matches(context.Background(), mustURL(t, "http://acme.test/.env"), notFound, probe),
		"a 404 page says the same about every path, so matching it is a host-wide finding")
	require.Zero(t, probes.Load(), "an error response is never compared, so it needs no baseline")

	ok := Response{StatusCode: http.StatusOK, Body: "DB_PASSWORD=hunter2"}
	require.False(t, d.Matches(context.Background(), mustURL(t, "http://acme.test/.env"), ok, probe))
	require.EqualValues(t, 1, probes.Load(), "a host that answers 404 stops the baseline at the first probe")
}

func TestRootIsNeverProbed(t *testing.T) {
	probe, probes := prober(func(string) Response { return Response{StatusCode: http.StatusOK, Body: spaShell} })
	d := New(0)

	for _, raw := range []string{"http://acme.test", "http://acme.test/", "http://acme.test/?q=1"} {
		require.False(t, d.Matches(context.Background(), mustURL(t, raw), Response{StatusCode: http.StatusOK, Body: spaShell}, probe), raw)
	}
	require.Zero(t, probes.Load(), "the home page is the page itself, not an answer for a missing path")
}

func TestReflectedPathIsIgnored(t *testing.T) {
	page := func(path string) Response {
		return Response{
			StatusCode: http.StatusFound,
			Location:   "/login?redirectTo=" + url.QueryEscape(path),
			Body:       `<a href="/login?redirectTo=` + url.QueryEscape(path) + `">Found</a>. Page ` + path + ` needs a login.`,
		}
	}
	probe, _ := prober(page)
	d := New(0)

	got := d.Matches(context.Background(), mustURL(t, "http://acme.test/.git/config"), page("/.git/config"), probe)
	require.True(t, got, "a login redirect that echoes the path is the same answer for every path")
}

func TestUnstableHostIsNotCalibrated(t *testing.T) {
	probe, _ := prober(func(string) Response {
		return Response{StatusCode: http.StatusOK, Body: strings.Repeat(rand.Text()+" ", 20)}
	})
	d := New(0)

	got := d.Matches(context.Background(), mustURL(t, "http://acme.test/admin"), Response{StatusCode: http.StatusOK, Body: "Admin console"}, probe)
	require.False(t, got, "a host with no stable answer for missing paths gives nothing to discount")
}

func TestDynamicTokensAreIgnored(t *testing.T) {
	page := func() Response {
		return Response{StatusCode: http.StatusOK, Body: spaShell + `<meta name="csrf" content="` + rand.Text() + `"> rendered at ` + "1730000000123"}
	}
	probe, _ := prober(func(string) Response { return page() })
	d := New(0)

	require.True(t, d.Matches(context.Background(), mustURL(t, "http://acme.test/backup.zip"), page(), probe))
}

func TestBaselineIsSharedPerShape(t *testing.T) {
	probe, probes := prober(func(string) Response { return Response{StatusCode: http.StatusOK, Body: spaShell} })
	d := New(0)
	shell := Response{StatusCode: http.StatusOK, Body: spaShell}
	ctx := context.Background()

	d.Matches(ctx, mustURL(t, "http://acme.test/a.php"), shell, probe)
	d.Matches(ctx, mustURL(t, "http://acme.test/b.php"), shell, probe)
	require.EqualValues(t, samples, probes.Load(), "templates hitting the same shape reuse one baseline")

	d.Matches(ctx, mustURL(t, "http://acme.test/a.json"), shell, probe)
	d.Matches(ctx, mustURL(t, "http://acme.test/admin/a.php"), shell, probe)
	d.Matches(ctx, mustURL(t, "http://acme.test/api/v1/b.php"), shell, probe)
	d.Matches(ctx, mustURL(t, "https://acme.test/a.php"), shell, probe)
	require.EqualValues(t, 4*samples, probes.Load(), "another extension, nesting or origin may be routed elsewhere")
}

func TestProbeShapes(t *testing.T) {
	cases := map[string]*regexp.Regexp{
		"http://acme.test/.env":               regexp.MustCompile(`^/\.RANDOM$`),
		"http://acme.test/admin/":             regexp.MustCompile(`^/RANDOM/$`),
		"http://acme.test/Backup.ZIP":         regexp.MustCompile(`^/RANDOM\.zip$`),
		"http://acme.test/wp-admin/x.php?a=1": regexp.MustCompile(`^/[a-z2-7]{26}/RANDOM\.php$`),
		"http://acme.test/actuator/env":       regexp.MustCompile(`^/[a-z2-7]{26}/RANDOM$`),
	}
	for raw, want := range cases {
		_, shape := shapeOf(mustURL(t, raw))
		require.Regexp(t, want, shape("RANDOM"), raw)
	}
}

// Swagger UI mounted at /api-docs/ answers every path below it with itself.
// Probing inside that directory would call a real exposure a catch-all page.
func TestAppMountedInDirectoryIsNotCatchAll(t *testing.T) {
	const swaggerUI = `<html><head><title>Swagger UI</title></head><body><div id="swagger-ui"></div><script src="swagger-ui-bundle.js"></script></body></html>`
	probe, _ := prober(func(path string) Response {
		if strings.HasPrefix(path, "/api-docs/") {
			return Response{StatusCode: http.StatusOK, Body: swaggerUI}
		}
		return Response{StatusCode: http.StatusOK, Body: spaShell}
	})
	d := New(0)

	got := d.Matches(context.Background(), mustURL(t, "http://acme.test/api-docs/swagger.json"), Response{StatusCode: http.StatusOK, Body: swaggerUI}, probe)
	require.False(t, got)
}

func TestFailedProbeDisablesCalibration(t *testing.T) {
	d := New(0)
	probe := func(context.Context, string) (Response, error) { return Response{}, errors.New("connection reset") }

	require.False(t, d.Matches(context.Background(), mustURL(t, "http://acme.test/.env"), Response{StatusCode: http.StatusOK, Body: spaShell}, probe))
}
