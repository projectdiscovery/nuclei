package runner

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestValidateReplayProxy(t *testing.T) {
	for _, valid := range []string{"", "http://127.0.0.1:8080", "https://proxy.example:8443", "socks5://127.0.0.1:1080"} {
		require.NoError(t, validateReplayProxy(valid), valid)
	}
	for _, invalid := range []string{"127.0.0.1:8080", "ftp://127.0.0.1:21", "http://", "://bad"} {
		require.Error(t, validateReplayProxy(invalid), invalid)
	}
}

type envState struct {
	val string
	set bool
}

func saveAndRestoreProxyEnv(t *testing.T) {
	t.Helper()
	original := make(map[string]envState, len(proxyEnvVars))
	for _, env := range proxyEnvVars {
		val, set := os.LookupEnv(env)
		original[env] = envState{val: val, set: set}
		_ = os.Unsetenv(env)
	}

	t.Cleanup(func() {
		for env, state := range original {
			if state.set {
				_ = os.Setenv(env, state.val)
			} else {
				_ = os.Unsetenv(env)
			}
		}
	})
}

func TestSetProxyEnv(t *testing.T) {
	saveAndRestoreProxyEnv(t)

	testProxy := "http://127.0.0.1:8080"
	setProxyEnv(testProxy)

	for _, env := range proxyEnvVars {
		require.Equal(t, testProxy, os.Getenv(env), "expected %s to be set", env)
	}
}

func TestLoadProxyServers_ProxyInternal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Run("proxy internal enabled sets all env vars", func(t *testing.T) {
		saveAndRestoreProxyEnv(t)

		options := &types.Options{
			Proxy:         goflags.StringSlice{server.URL},
			ProxyInternal: true,
			Timeout:       5,
			Logger:        &gologger.Logger{},
		}
		err := loadProxyServers(options)
		require.NoError(t, err)
		for _, env := range proxyEnvVars {
			require.Equal(t, server.URL, os.Getenv(env), "expected %s to be set", env)
		}
	})

	t.Run("proxy internal disabled does not set env vars", func(t *testing.T) {
		saveAndRestoreProxyEnv(t)

		options := &types.Options{
			Proxy:         goflags.StringSlice{server.URL},
			ProxyInternal: false,
			Timeout:       5,
			Logger:        &gologger.Logger{},
		}
		err := loadProxyServers(options)
		require.NoError(t, err)
		for _, env := range proxyEnvVars {
			require.Empty(t, os.Getenv(env), "expected %s not to be set", env)
		}
	})
}
