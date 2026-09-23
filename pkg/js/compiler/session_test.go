package compiler

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestSessionInjectsProxyAndTimeoutContext(t *testing.T) {
	runtime := goja.New()
	program, err := goja.Compile("test.js", `
		function run() {
			return { success: true };
		}
		run();
	`, false)
	require.NoError(t, err)

	var sawProxy string
	var sawTimeout time.Duration
	var sawHeaders []string
	proxyURL := "http://127.0.0.1:8080"
	customHeaders := []string{"X-Global: value"}
	timeouts := &types.Timeouts{
		TcpReadTimeout:             12 * time.Second,
		JsCompilerExecutionTimeout: 5 * time.Second,
	}

	opts := &ExecuteOptions{
		ExecutionId:     "session-proxy-test",
		ProxyURL:        proxyURL,
		CustomHeaders:   customHeaders,
		TimeoutVariants: timeouts,
		Callback: func(rt *goja.Runtime) error {
			if v, ok := rt.GetContextValue("proxyURL"); ok {
				sawProxy, _ = v.(string)
			}
			if v, ok := rt.GetContextValue("timeoutVariants"); ok {
				if tv, ok := v.(*types.Timeouts); ok && tv != nil {
					sawTimeout = tv.TcpReadTimeout
				}
			}
			if v, ok := rt.GetContextValue("customHeaders"); ok {
				sawHeaders, _ = v.([]string)
			}
			if v, ok := rt.GetContextValue("ctx"); ok {
				executionCtx, _ := v.(context.Context)
				require.Equal(t, proxyURL, executionCtx.Value("proxyURL"))
				require.Equal(t, timeouts, executionCtx.Value("timeoutVariants"))
				require.Equal(t, customHeaders, executionCtx.Value("customHeaders"))
			}
			return nil
		},
	}

	_, err = executeWithRuntime(context.Background(), runtime, program, NewExecuteArgs(), opts, nil)
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:8080", sawProxy)
	require.Equal(t, 12*time.Second, sawTimeout)
	require.Equal(t, customHeaders, sawHeaders)

	_, ok := runtime.GetContextValue("proxyURL")
	require.False(t, ok, "proxyURL should be cleaned up after execution")
	_, ok = runtime.GetContextValue("timeoutVariants")
	require.False(t, ok, "timeoutVariants should be cleaned up after execution")
	_, ok = runtime.GetContextValue("customHeaders")
	require.False(t, ok, "customHeaders should be cleaned up after execution")
}

func TestSessionAppliesOptionsToJSHTTP(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "example.com", r.Host)
		_, _ = io.WriteString(w, r.Header.Get("X-Global"))
	}))
	t.Cleanup(proxy.Close)

	executionID := "session-js-http"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	source := `
		const http = require("nuclei/http");
		http.Get("http://example.com/through-proxy").Body;
	`
	program, err := goja.Compile("test.js", source, false)
	require.NoError(t, err)

	result, err := executeWithRuntime(t.Context(), createNewRuntime(), program, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId:   executionID,
		ProxyURL:      proxy.URL,
		CustomHeaders: []string{"X-Global: inherited"},
		TimeoutVariants: &types.Timeouts{
			HttpTimeout:                2 * time.Second,
			JsCompilerExecutionTimeout: 5 * time.Second,
		},
	}, nil)
	require.NoError(t, err)
	require.Equal(t, "inherited", result.String())
}
