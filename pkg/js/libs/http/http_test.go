package http

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func withExec(executionID string) context.Context {
	// Nuclei JS runtime uses a string context key; keep tests aligned.
	return context.WithValue(context.Background(), "executionId", executionID) //nolint:staticcheck // SA1029
}

func initExec(t *testing.T, options *types.Options) string {
	t.Helper()
	executionID := "http-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	options.ExecutionId = executionID
	require.NoError(t, protocolstate.Init(options))
	t.Cleanup(func() { protocolstate.Close(executionID) })
	return executionID
}

func newRuntimeClient(t *testing.T, executionID string, opts Options) *Client {
	t.Helper()
	runtime := goja.New()
	runtime.SetContextValue("executionId", executionID)
	runtime.SetContextValue("ctx", context.Background())

	obj, err := runtime.New(runtime.ToValue(NewClient), runtime.ToValue(opts))
	require.NoError(t, err)
	client, ok := obj.Export().(*Client)
	require.True(t, ok)
	return client
}

func TestClientGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "ok")
		_, _ = io.WriteString(w, "hello")
	}))
	t.Cleanup(srv.Close)

	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{DisableRedirects: true})

	ctx := withExec(executionID)
	resp, err := client.Get(ctx, srv.URL+"/")
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "hello", resp.Body)
	require.Equal(t, "ok", resp.GetHeader("X-Test"))
}

func TestClientFollowsRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "done")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{})
	ctx := withExec(executionID)
	resp, err := client.Get(ctx, srv.URL+"/a")
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "done", resp.Body)
}

func TestClientHostDenied(t *testing.T) {
	executionID := initExec(t, &types.Options{ExcludeTargets: []string{"203.0.113.50"}})
	client := newRuntimeClient(t, executionID, Options{})
	ctx := withExec(executionID)
	_, err := client.Get(ctx, "http://203.0.113.50/")
	require.Error(t, err)
	require.Contains(t, err.Error(), "203.0.113.50")
}

func TestPackageGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "pkg")
	}))
	t.Cleanup(srv.Close)

	executionID := initExec(t, &types.Options{})
	ctx := withExec(executionID)
	resp, err := Get(ctx, srv.URL)
	require.NoError(t, err)
	require.Equal(t, "pkg", resp.Body)
}

func TestClientCookies(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc"})
		_, _ = io.WriteString(w, "set")
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sid")
		if err != nil {
			http.Error(w, "missing", 400)
			return
		}
		_, _ = io.WriteString(w, c.Value)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{})
	ctx := withExec(executionID)

	_, err := client.Get(ctx, srv.URL+"/set")
	require.NoError(t, err)
	resp, err := client.Get(ctx, srv.URL+"/echo")
	require.NoError(t, err)
	require.Equal(t, "abc", resp.Body)
}

func TestClientPost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)

	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{})
	ctx := withExec(executionID)
	resp, err := client.Post(ctx, srv.URL, "payload")
	require.NoError(t, err)
	require.Equal(t, "payload", resp.Body)
}

func TestMaxBodyBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("a", 100))
	}))
	t.Cleanup(srv.Close)

	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{MaxBodyBytes: 10})
	ctx := withExec(executionID)
	_, err := client.Get(ctx, srv.URL)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds")
}

func TestDialUsesFastdialer(t *testing.T) {
	// Ensure loopback httptest still works through fastdialer after Init.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "fd")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	executionID := initExec(t, &types.Options{})
	ctx := withExec(executionID)
	resp, err := Get(ctx, "http://"+ln.Addr().String()+"/")
	require.NoError(t, err)
	require.Equal(t, "fd", resp.Body)
}

func TestClientSetHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("X-Custom"))
	}))
	t.Cleanup(srv.Close)

	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{})
	client.SetHeader("X-Custom", "from-client")
	ctx := withExec(executionID)
	resp, err := client.Get(ctx, srv.URL)
	require.NoError(t, err)
	require.Equal(t, "from-client", resp.Body)
}

func TestClientInheritsGlobalHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("X-Global")+"|"+r.Header.Get("X-Override"))
	}))
	t.Cleanup(srv.Close)

	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{})
	client.SetHeader("X-Override", "client")

	ctx := withExec(executionID)
	ctx = context.WithValue(ctx, "customHeaders", []string{ //nolint:staticcheck
		"X-Global: from-cli",
		"X-Override: global",
		"invalid",
	})
	resp, err := client.Get(ctx, srv.URL)
	require.NoError(t, err)
	require.Equal(t, "from-cli|client", resp.Body)
}

func TestClientUsesConfiguredProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "example.com", r.Host)
		require.Equal(t, "/through-proxy", r.URL.Path)
		_, _ = io.WriteString(w, "proxied")
	}))
	t.Cleanup(proxy.Close)

	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{})
	ctx := withExec(executionID)
	ctx = context.WithValue(ctx, "proxyURL", proxy.URL) //nolint:staticcheck

	resp, err := client.Get(ctx, "http://example.com/through-proxy")
	require.NoError(t, err)
	require.Equal(t, "proxied", resp.Body)
}

func TestClientUsesConfiguredProxyForHTTPS(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secure-proxied")
	}))
	t.Cleanup(target.Close)

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodConnect, r.Method)
		upstream, err := net.Dial("tcp", r.Host)
		require.NoError(t, err)
		defer func() { _ = upstream.Close() }()

		hijacker, ok := w.(http.Hijacker)
		require.True(t, ok)
		client, rw, err := hijacker.Hijack()
		require.NoError(t, err)
		defer func() { _ = client.Close() }()

		_, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		require.NoError(t, err)
		require.NoError(t, rw.Flush())

		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(upstream, client)
			close(done)
		}()
		_, _ = io.Copy(client, upstream)
		<-done
	}))
	t.Cleanup(proxy.Close)

	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{})
	ctx := withExec(executionID)
	ctx = context.WithValue(ctx, "proxyURL", proxy.URL) //nolint:staticcheck

	resp, err := client.Get(ctx, target.URL)
	require.NoError(t, err)
	require.Equal(t, "secure-proxied", resp.Body)
}

func TestClientRejectsInvalidConfiguredProxy(t *testing.T) {
	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{})
	ctx := withExec(executionID)
	ctx = context.WithValue(ctx, "proxyURL", "socks5://127.0.0.1:1080") //nolint:staticcheck

	_, err := client.Get(ctx, "http://example.com/")
	require.ErrorContains(t, err, "must use http or https")
}

func TestClientUsesConfiguredHTTPTimeout(t *testing.T) {
	timeouts := &types.Timeouts{HttpTimeout: 7 * time.Second}
	ctx := context.WithValue(context.Background(), "timeoutVariants", timeouts) //nolint:staticcheck
	require.Equal(t, 7*time.Second, requestTimeout(ctx, 0))
	require.Equal(t, 2*time.Second, requestTimeout(ctx, 2), "client option must override the global timeout")

	runtime := goja.New()
	runtime.SetContextValue("executionId", "timeout-test")
	runtime.SetContextValue("timeoutVariants", timeouts)
	obj, err := runtime.New(runtime.ToValue(NewClient))
	require.NoError(t, err)
	client, ok := obj.Export().(*Client)
	require.True(t, ok)
	require.Equal(t, 7, client.TimeoutSeconds)
}

func TestClientHead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodHead, r.Method)
		w.Header().Set("X-Head", "1")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{})
	ctx := withExec(executionID)
	resp, err := client.Head(ctx, srv.URL)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.Equal(t, "1", resp.GetHeader("X-Head"))
	require.Empty(t, resp.Body)
}

func TestClientRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = io.WriteString(w, r.Method+":"+string(b))
	}))
	t.Cleanup(srv.Close)

	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{})
	ctx := withExec(executionID)
	resp, err := client.Request(ctx, "put", srv.URL, "xyz")
	require.NoError(t, err)
	require.Equal(t, "PUT:xyz", resp.Body)

	resp, err = client.Request(ctx, "", srv.URL, "")
	require.NoError(t, err)
	require.Equal(t, "GET:", resp.Body)
}

func TestPackageHeadPostRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/head", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodHead, r.Method)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/req", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Method)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	executionID := initExec(t, &types.Options{})
	ctx := withExec(executionID)

	head, err := Head(ctx, srv.URL+"/head")
	require.NoError(t, err)
	require.Equal(t, 200, head.StatusCode)

	post, err := Post(ctx, srv.URL+"/post", "body")
	require.NoError(t, err)
	require.Equal(t, "body", post.Body)

	req, err := Request(ctx, "DELETE", srv.URL+"/req", "")
	require.NoError(t, err)
	require.Equal(t, "DELETE", req.Body)
}

func TestClientDisableRedirects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "should-not-follow")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{DisableRedirects: true})
	ctx := withExec(executionID)
	resp, err := client.Get(ctx, srv.URL+"/a")
	require.NoError(t, err)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.NotContains(t, resp.Body, "should-not-follow")
}

func TestClientDisableCookie(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc"})
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("sid"); err != nil {
			_, _ = io.WriteString(w, "missing")
			return
		}
		_, _ = io.WriteString(w, "present")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{DisableCookie: true})
	ctx := withExec(executionID)
	_, err := client.Get(ctx, srv.URL+"/set")
	require.NoError(t, err)
	resp, err := client.Get(ctx, srv.URL+"/echo")
	require.NoError(t, err)
	require.Equal(t, "missing", resp.Body)
}

func TestRedirectHostDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://203.0.113.50/x", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	executionID := initExec(t, &types.Options{ExcludeTargets: []string{"203.0.113.50"}})
	client := newRuntimeClient(t, executionID, Options{})
	ctx := withExec(executionID)
	_, err := client.Get(ctx, srv.URL+"/")
	require.Error(t, err)
	require.Contains(t, err.Error(), "203.0.113.50")
}

func TestInvalidURL(t *testing.T) {
	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{})
	ctx := withExec(executionID)
	_, err := client.Get(ctx, "not-a-url")
	require.Error(t, err)
	_, err = client.Get(ctx, "/relative")
	require.Error(t, err)
}

func TestGetHeader(t *testing.T) {
	require.Equal(t, "", (*Response)(nil).GetHeader("X"))

	r := &Response{Headers: map[string]string{"Content-Type": "text/plain"}}
	require.Equal(t, "text/plain", r.GetHeader("Content-Type"))
	require.Equal(t, "text/plain", r.GetHeader("content-type"))
	require.Equal(t, "", r.GetHeader("Missing"))

	r2 := &Response{header: http.Header{"X-A": []string{"b"}}}
	require.Equal(t, "b", r2.GetHeader("x-a"))

	r3 := &Response{}
	require.Equal(t, "", r3.GetHeader("X"))
}

func TestNewClientOptions(t *testing.T) {
	executionID := initExec(t, &types.Options{})
	client := newRuntimeClient(t, executionID, Options{
		TimeoutSeconds:   5,
		MaxRedirects:     3,
		MaxBodyBytes:     1024,
		DisableRedirects: true,
		DisableCookie:    true,
	})
	require.Equal(t, 5, client.TimeoutSeconds)
	require.False(t, client.FollowRedirects)
	require.Equal(t, 0, client.MaxRedirects)
	require.Equal(t, 1024, client.MaxBodyBytes)
	require.True(t, client.DisableCookie)
}

func TestMissingExecutionID(t *testing.T) {
	c := &Client{FollowRedirects: true, MaxRedirects: 1, TimeoutSeconds: 1, MaxBodyBytes: 100}
	_, err := c.Get(context.Background(), "http://127.0.0.1/")
	require.Error(t, err)
	require.Contains(t, err.Error(), "executionId")
}
