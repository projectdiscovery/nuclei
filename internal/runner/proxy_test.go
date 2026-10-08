package runner

import (
	"testing"

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
