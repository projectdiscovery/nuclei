package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	inputtypes "github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/stretchr/testify/require"
)

func TestFuzzingReissuedCookieReplacesCapturedCookie(t *testing.T) {
	for _, disableCookie := range []bool{false, true} {
		name := "reuse enabled"
		if disableCookie {
			name = "reuse disabled"
		}
		t.Run(name, func(t *testing.T) {
			received := make(chan string, 3)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received <- r.Header.Get("Cookie")
				if cookie, err := r.Cookie("session"); err == nil && cookie.Value == "old'" {
					http.SetCookie(w, &http.Cookie{Name: "session", Value: "reissued", Path: "/"})
				}
			}))
			defer server.Close()

			options := testutils.DefaultOptions.Copy()
			options.SetExecutionID(t.Name())
			options.DAST = true
			testutils.Init(options)
			t.Cleanup(func() { testutils.Cleanup(options) })
			executorOptions := testutils.NewMockExecuterOptions(options, nil)
			t.Cleanup(executorOptions.RateLimiter.Stop)
			request := &Request{
				DisableCookie: disableCookie,
				Fuzzing: []*fuzz.Rule{
					{Part: "cookie", Type: "postfix", Mode: "single", Keys: []string{"session"}, Fuzz: fuzz.SliceOrMapSlice{Value: []string{"'"}}},
					{Part: "header", Type: "postfix", Mode: "single", Keys: []string{"X-Test"}, Fuzz: fuzz.SliceOrMapSlice{Value: []string{"'", "test"}}},
				},
			}
			require.NoError(t, request.Compile(executorOptions))
			captured, err := inputtypes.ParseRawRequestWithURL("GET / HTTP/1.1\r\nHost: "+server.Listener.Addr().String()+"\r\nCookie: session=old; preference=dark\r\nX-Test: baseline\r\n\r\n", server.URL)
			require.NoError(t, err)
			input := contextargs.NewWithInput(context.Background(), server.URL)
			input.MetaInput.ReqResp = captured

			var dumps []string
			err = request.executeFuzzingRule(input, nil, func(event *output.InternalWrappedEvent) {
				dumps = append(dumps, event.InternalEvent["request"].(string))
			})
			require.NoError(t, err)
			require.Len(t, dumps, 3)
			require.Len(t, received, 3)
			require.Equal(t, "session=old'; preference=dark", <-received)
			wantCookie := "preference=dark; session=reissued"
			if disableCookie {
				wantCookie = "session=old; preference=dark"
			}
			for _, dump := range dumps[1:] {
				require.Equal(t, wantCookie, <-received)
				require.Contains(t, dump, "Cookie: "+wantCookie+"\r\n")
				require.Equal(t, 1, strings.Count(dump, "session="))
			}
			baseRequest, err := captured.BuildRequest()
			require.NoError(t, err)
			require.Equal(t, "session=old; preference=dark", baseRequest.Header.Get("Cookie"))
		})
	}
}

func TestFuzzingPreservesConfiguredCookieAuth(t *testing.T) {
	for _, authType := range []string{"Cookie", "Header", "Dynamic"} {
		t.Run(authType, func(t *testing.T) {
			received := make(chan string, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cookie, err := r.Cookie("session")
				if err == nil {
					received <- cookie.Value
				} else {
					received <- ""
				}
			}))
			defer server.Close()

			options := testutils.DefaultOptions.Copy()
			options.SetExecutionID(t.Name())
			options.DAST = true
			testutils.Init(options)
			t.Cleanup(func() { testutils.Cleanup(options) })
			executorOptions := testutils.NewMockExecuterOptions(options, nil)
			t.Cleanup(executorOptions.RateLimiter.Stop)
			executorOptions.AuthProvider = newCookieAuthProvider(t, authType, server.Listener.Addr().String(), "session")
			request := &Request{Fuzzing: []*fuzz.Rule{
				{Part: "header", Type: "postfix", Mode: "single", Keys: []string{"X-Test"}, Fuzz: fuzz.SliceOrMapSlice{Value: []string{"'", "test"}}},
			}}
			require.NoError(t, request.Compile(executorOptions))
			captured, err := inputtypes.ParseRawRequestWithURL("GET / HTTP/1.1\r\nHost: "+server.Listener.Addr().String()+"\r\nCookie: session=captured\r\nX-Test: baseline\r\n\r\n", server.URL)
			require.NoError(t, err)
			input := contextargs.NewWithInput(context.Background(), server.URL)
			input.MetaInput.ReqResp = captured
			input.CookieJar.SetCookies(captured.URL.URL, []*http.Cookie{{Name: "session", Value: "stale", Path: "/"}})
			err = request.executeFuzzingRule(input, nil, func(event *output.InternalWrappedEvent) {
				require.Contains(t, event.InternalEvent["request"].(string), "session=configured")
			})
			require.NoError(t, err)
			require.Len(t, received, 2)
			for i := 0; i < 2; i++ {
				require.Equal(t, "configured", <-received)
			}
		})
	}
}

func TestFuzzingPreservesCookiePayload(t *testing.T) {
	for _, seeded := range []bool{false, true} {
		for _, payload := range []string{"'", `"`} {
			name := "empty jar/" + payload
			if seeded {
				name = "stored cookie/" + payload
			}
			t.Run(name, func(t *testing.T) {
				received := make(chan string, 1)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					received <- r.Header.Get("Cookie")
				}))
				defer server.Close()
				options := testutils.DefaultOptions.Copy()
				options.SetExecutionID(t.Name())
				options.DAST = true
				testutils.Init(options)
				t.Cleanup(func() { testutils.Cleanup(options) })
				executorOptions := testutils.NewMockExecuterOptions(options, nil)
				t.Cleanup(executorOptions.RateLimiter.Stop)
				request := &Request{Fuzzing: []*fuzz.Rule{
					{Part: "cookie", Type: "postfix", Mode: "single", Keys: []string{"session"}, Fuzz: fuzz.SliceOrMapSlice{Value: []string{payload}}},
				}}
				require.NoError(t, request.Compile(executorOptions))
				captured, err := inputtypes.ParseRawRequestWithURL("GET / HTTP/1.1\r\nHost: "+server.Listener.Addr().String()+"\r\nCookie: session=old; preference=dark\r\n\r\n", server.URL)
				require.NoError(t, err)
				input := contextargs.NewWithInput(context.Background(), server.URL)
				input.MetaInput.ReqResp = captured
				if seeded {
					input.CookieJar.SetCookies(captured.URL.URL, []*http.Cookie{{Name: "session", Value: "stored", Path: "/"}})
				}
				var dumps []string
				require.NoError(t, request.executeFuzzingRule(input, nil, func(event *output.InternalWrappedEvent) {
					dumps = append(dumps, event.InternalEvent["request"].(string))
				}))
				require.Len(t, received, 1)
				require.Len(t, dumps, 1)
				want := "session=old" + payload + "; preference=dark"
				require.Equal(t, want, <-received)
				require.Contains(t, dumps[0], "Cookie: "+want+"\r\n")
				base, err := captured.BuildRequest()
				require.NoError(t, err)
				require.Equal(t, "session=old; preference=dark", base.Header.Get("Cookie"))
			})
		}
	}
}

func TestFuzzingCookieTargetsAndJarUpdates(t *testing.T) {
	kv := mapsutil.NewOrderedMap[string, string]()
	kv.Set("session", "old'")
	kv.Set("account", `base"`)
	tests := []struct {
		name string
		rule *fuzz.Rule
		want []string
	}{
		{name: "single targets", rule: &fuzz.Rule{Part: "cookie", Type: "postfix", Mode: "single", Keys: []string{"session", "account"}, Fuzz: fuzz.SliceOrMapSlice{Value: []string{"'"}}}, want: []string{"session=old'; account=stored; preference=fresh", "account=base'; session=reissued; preference=fresh"}},
		{name: "consecutive payloads", rule: &fuzz.Rule{Part: "cookie", Type: "postfix", Mode: "single", Keys: []string{"session"}, Fuzz: fuzz.SliceOrMapSlice{Value: []string{"'", `"`}}}, want: []string{"session=old'; account=stored; preference=fresh", `session=old"; account=stored; preference=fresh`}},
		{name: "multiple targets", rule: &fuzz.Rule{Part: "cookie", Type: "postfix", Mode: "multiple", Keys: []string{"session", "account"}, Fuzz: fuzz.SliceOrMapSlice{Value: []string{"'"}}}, want: []string{"session=old'; account=base'; preference=fresh"}},
		{name: "multiple key values", rule: &fuzz.Rule{Part: "cookie", Type: "replace", Mode: "multiple", Fuzz: fuzz.SliceOrMapSlice{KV: &kv}}, want: []string{`session=old'; account=base"; preference=fresh`}},
		{name: "single key values", rule: &fuzz.Rule{Part: "cookie", Type: "replace", Mode: "single", Fuzz: fuzz.SliceOrMapSlice{KV: &kv}}, want: []string{"session=old'; account=stored; preference=fresh", `account=base"; session=reissued; preference=fresh`}},
		{name: "payload equals captured value", rule: &fuzz.Rule{Part: "cookie", Type: "replace", Mode: "single", Keys: []string{"session"}, Fuzz: fuzz.SliceOrMapSlice{Value: []string{"old"}}}, want: []string{"session=old; account=stored; preference=fresh"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			received := make(chan string, len(test.want))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received <- r.Header.Get("Cookie")
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "reissued", Path: "/"})
			}))
			defer server.Close()
			options := testutils.DefaultOptions.Copy()
			options.SetExecutionID(t.Name())
			options.DAST = true
			testutils.Init(options)
			t.Cleanup(func() { testutils.Cleanup(options) })
			executorOptions := testutils.NewMockExecuterOptions(options, nil)
			t.Cleanup(executorOptions.RateLimiter.Stop)
			request := &Request{Fuzzing: []*fuzz.Rule{test.rule}}
			require.NoError(t, request.Compile(executorOptions))
			captured, err := inputtypes.ParseRawRequestWithURL("GET / HTTP/1.1\r\nHost: "+server.Listener.Addr().String()+"\r\nCookie: session=old; account=base; preference=dark\r\n\r\n", server.URL)
			require.NoError(t, err)
			input := contextargs.NewWithInput(context.Background(), server.URL)
			input.MetaInput.ReqResp = captured
			input.CookieJar.SetCookies(captured.URL.URL, []*http.Cookie{{Name: "session", Value: "stored", Path: "/"}, {Name: "account", Value: "stored", Path: "/"}, {Name: "preference", Value: "fresh", Path: "/"}})
			var dumps []string
			require.NoError(t, request.executeFuzzingRule(input, nil, func(event *output.InternalWrappedEvent) {
				dumps = append(dumps, event.InternalEvent["request"].(string))
			}))
			require.Len(t, received, len(test.want))
			require.Len(t, dumps, len(test.want))
			for i, want := range test.want {
				require.Equal(t, want, <-received)
				require.Contains(t, dumps[i], "Cookie: "+want+"\r\n")
			}
			var session string
			for _, cookie := range input.CookieJar.Cookies(captured.URL.URL) {
				if cookie.Name == "session" {
					session = cookie.Value
				}
			}
			require.Equal(t, "reissued", session)
		})
	}
}

func TestFuzzingPreservesCookiePayloadWithAuth(t *testing.T) {
	for _, authType := range []string{"Cookie", "Header", "Dynamic"} {
		for _, authCookie := range []string{"session", "auth"} {
			t.Run(authType+"/"+authCookie, func(t *testing.T) {
				received := make(chan string, 3)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					received <- r.Header.Get("Cookie")
				}))
				defer server.Close()
				options := testutils.DefaultOptions.Copy()
				options.SetExecutionID(t.Name())
				options.DAST = true
				testutils.Init(options)
				t.Cleanup(func() { testutils.Cleanup(options) })
				executorOptions := testutils.NewMockExecuterOptions(options, nil)
				t.Cleanup(executorOptions.RateLimiter.Stop)
				executorOptions.AuthProvider = newCookieAuthProvider(t, authType, server.Listener.Addr().String(), authCookie)
				payloads := []string{"'", `"`, ";probe=value"}
				request := &Request{Fuzzing: []*fuzz.Rule{
					{Part: "cookie", Type: "postfix", Mode: "single", Keys: []string{"session"}, Fuzz: fuzz.SliceOrMapSlice{Value: payloads}},
				}}
				require.NoError(t, request.Compile(executorOptions))
				captured, err := inputtypes.ParseRawRequestWithURL("GET / HTTP/1.1\r\nHost: "+server.Listener.Addr().String()+"\r\nCookie: session=old; preference=dark\r\n\r\n", server.URL)
				require.NoError(t, err)
				input := contextargs.NewWithInput(context.Background(), server.URL)
				input.MetaInput.ReqResp = captured
				input.CookieJar.SetCookies(captured.URL.URL, []*http.Cookie{{Name: "session", Value: "stored", Path: "/"}})
				var dumps []string
				require.NoError(t, request.executeFuzzingRule(input, nil, func(event *output.InternalWrappedEvent) {
					dumps = append(dumps, event.InternalEvent["request"].(string))
				}))
				require.Len(t, received, len(payloads))
				require.Len(t, dumps, len(payloads))
				for i, payload := range payloads {
					header := <-received
					require.Contains(t, header, "session=old"+payload)
					require.Equal(t, 1, strings.Count(header, "session="))
					if strings.Contains(payload, "probe=") {
						require.Equal(t, 1, strings.Count(header, "probe="))
					}
					require.Contains(t, dumps[i], "Cookie: "+header+"\r\n")
					if authCookie != "session" {
						require.Contains(t, header, "auth=configured")
					}
				}
			})
		}
	}
}

func newCookieAuthProvider(t *testing.T, authType, domain, cookieName string) authprovider.AuthProvider {
	t.Helper()
	secretFile := filepath.Join(t.TempDir(), "secrets.yaml")
	secret := "static:\n  - type: Cookie\n    domains: [\"" + domain + "\"]\n    cookies:\n      - key: " + cookieName + "\n        value: configured\n"
	var fetchSecret authx.LazyFetchSecret
	switch authType {
	case "Header":
		secret = "static:\n  - type: Header\n    domains: [\"" + domain + "\"]\n    headers:\n      - key: Cookie\n        value: " + cookieName + "=configured\n"
	case "Dynamic":
		secret = "dynamic:\n  - template: login.yaml\n    variables:\n      - key: user\n        value: test\n    type: Cookie\n    domains: [\"" + domain + "\"]\n    cookies:\n      - key: " + cookieName + "\n        value: '{{credential}}'\n"
		fetchSecret = func(dynamic *authx.Dynamic) error {
			dynamic.Extracted = map[string]interface{}{"credential": "configured"}
			return nil
		}
	}
	require.NoError(t, os.WriteFile(secretFile, []byte(secret), 0o600))
	provider, err := authprovider.NewFileAuthProvider(secretFile, fetchSecret)
	require.NoError(t, err)
	return provider
}

func TestFuzzingPreservesCookiePayloadOnRedirect(t *testing.T) {
	for _, payload := range []string{"'", `"`} {
		t.Run(payload, func(t *testing.T) {
			received := make(chan string, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received <- r.Header.Get("Cookie")
				if r.URL.Path == "/start" {
					http.SetCookie(w, &http.Cookie{Name: "session", Value: "reissued", Path: "/"})
					http.SetCookie(w, &http.Cookie{Name: "preference", Value: "fresh", Path: "/"})
					http.Redirect(w, r, "/target", http.StatusFound)
				}
			}))
			defer server.Close()
			options := testutils.DefaultOptions.Copy()
			options.SetExecutionID(t.Name())
			options.DAST = true
			testutils.Init(options)
			t.Cleanup(func() { testutils.Cleanup(options) })
			executorOptions := testutils.NewMockExecuterOptions(options, nil)
			t.Cleanup(executorOptions.RateLimiter.Stop)
			request := &Request{Redirects: true, MaxRedirects: 5, Fuzzing: []*fuzz.Rule{
				{Part: "cookie", Type: "postfix", Mode: "single", Keys: []string{"session"}, Fuzz: fuzz.SliceOrMapSlice{Value: []string{payload}}},
			}}
			require.NoError(t, request.Compile(executorOptions))
			captured, err := inputtypes.ParseRawRequestWithURL("GET /start HTTP/1.1\r\nHost: "+server.Listener.Addr().String()+"\r\nCookie: session=old; preference=dark\r\n\r\n", server.URL+"/start")
			require.NoError(t, err)
			input := contextargs.NewWithInput(context.Background(), server.URL+"/start")
			input.MetaInput.ReqResp = captured
			require.NoError(t, request.executeFuzzingRule(input, nil, func(*output.InternalWrappedEvent) {}))
			require.Len(t, received, 2)
			require.Equal(t, "session=old"+payload+"; preference=dark", <-received)
			require.Equal(t, "session=old"+payload+"; preference=fresh", <-received)
		})
	}
}

func TestFuzzingPreservesCookiePayloadFromProjectCache(t *testing.T) {
	for _, analyzer := range []bool{false, true} {
		name := "request dump"
		if analyzer {
			name = "analyzer follow-up"
		}
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			received := make(chan string, 3)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				received <- r.Header.Get("Cookie")
				_, _ = w.Write([]byte("<p>old\"</p>"))
			}))
			defer server.Close()
			options := testutils.DefaultOptions.Copy()
			options.SetExecutionID(t.Name())
			options.DAST = true
			testutils.Init(options)
			t.Cleanup(func() { testutils.Cleanup(options) })
			executorOptions := testutils.NewMockExecuterOptions(options, nil)
			t.Cleanup(executorOptions.RateLimiter.Stop)
			executorOptions.AuthProvider = newCookieAuthProvider(t, "Cookie", server.Listener.Addr().String(), "auth")
			cache, err := projectfile.New(&projectfile.Options{Path: filepath.Join(t.TempDir(), "cache"), Cleanup: true})
			require.NoError(t, err)
			defer cache.Close()
			executorOptions.ProjectFile = cache
			request := &Request{Fuzzing: []*fuzz.Rule{
				{Part: "cookie", Type: "postfix", Mode: "single", Keys: []string{"session"}, Fuzz: fuzz.SliceOrMapSlice{Value: []string{`"`}}},
			}}
			if analyzer {
				request.Analyzer = &analyzers.AnalyzerTemplate{Name: "xss_context"}
			}
			require.NoError(t, request.Compile(executorOptions))
			captured, err := inputtypes.ParseRawRequestWithURL("GET / HTTP/1.1\r\nHost: "+server.Listener.Addr().String()+"\r\nCookie: session=old; preference=dark\r\n\r\n", server.URL)
			require.NoError(t, err)
			input := contextargs.NewWithInput(context.Background(), server.URL)
			input.MetaInput.ReqResp = captured
			stored := []*http.Cookie{{Name: "session", Value: "stored", Path: "/"}}
			input.CookieJar.SetCookies(captured.URL.URL, stored)
			client := request.getHTTPClientForHost(captured.URL.Host)
			require.NotNil(t, client)
			client.HTTPClient.Jar.SetCookies(captured.URL.URL, stored)
			var dumps []string
			for i := 0; i < 2; i++ {
				require.NoError(t, request.executeFuzzingRule(input, nil, func(event *output.InternalWrappedEvent) {
					dumps = append(dumps, event.InternalEvent["request"].(string))
				}))
			}
			wantRequests := int32(1)
			if analyzer {
				wantRequests = 3 // one initial send and two analyzer follow-ups
			}
			require.Equal(t, wantRequests, requests.Load())
			require.Len(t, dumps, 2)
			for _, dump := range dumps {
				require.Contains(t, dump, `session=old"`)
			}
			for i := int32(0); i < wantRequests; i++ {
				require.Contains(t, <-received, `session=old"`)
			}
		})
	}
}

func TestFuzzingSignsCookiePayloadAfterAuth(t *testing.T) {
	verified := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		_, signedHeaders, _ := strings.Cut(authorization, "SignedHeaders=")
		signedHeaders, _, _ = strings.Cut(signedHeaders, ",")
		clone := r.Clone(r.Context())
		clone.URL.Scheme, clone.URL.Host = "http", r.Host
		clone.Header = make(http.Header)
		for _, name := range strings.Split(signedHeaders, ";") {
			if name != "host" {
				clone.Header[http.CanonicalHeaderKey(name)] = append([]string(nil), r.Header.Values(name)...)
			}
		}
		signedAt, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
		if err == nil {
			err = v4.NewSigner().SignHTTP(r.Context(), aws.Credentials{AccessKeyID: "test-key", SecretAccessKey: "test-secret"}, clone, r.Header.Get("X-Amz-Content-Sha256"), "sts", "us-east-2", signedAt)
		}
		if err == nil && clone.Header.Get("Authorization") != authorization {
			err = fmt.Errorf("signature does not match the cookie header received by the server")
		}
		verified <- err
	}))
	defer server.Close()
	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	options.DAST = true
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executorOptions := testutils.NewMockExecuterOptions(options, nil)
	t.Cleanup(executorOptions.RateLimiter.Stop)
	executorOptions.AuthProvider = newCookieAuthProvider(t, "Header", server.Listener.Addr().String(), "session")
	request := &Request{Signature: SignatureTypeHolder{Value: AWSSignature}, Fuzzing: []*fuzz.Rule{
		{Part: "cookie", Type: "postfix", Mode: "single", Keys: []string{"session"}, Fuzz: fuzz.SliceOrMapSlice{Value: []string{`"`}}},
	}}
	require.NoError(t, request.Compile(executorOptions))
	captured, err := inputtypes.ParseRawRequestWithURL("GET / HTTP/1.1\r\nHost: "+server.Listener.Addr().String()+"\r\nCookie: session=old\r\n\r\n", server.URL)
	require.NoError(t, err)
	input := contextargs.NewWithInput(context.Background(), server.URL)
	input.MetaInput.ReqResp = captured
	require.NoError(t, request.executeFuzzingRule(input, map[string]interface{}{"aws-id": "test-key", "aws-secret": "test-secret"}, func(*output.InternalWrappedEvent) {}))
	require.NoError(t, <-verified)
}
