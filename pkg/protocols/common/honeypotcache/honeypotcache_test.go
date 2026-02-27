package honeypotcache

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

func TestHoneypotCache(t *testing.T) {
	t.Run("basic honeypot detection", func(t *testing.T) {
		cache := New(50, false, 100)
		cache.SetTotalTemplates(10)

		ctx := &contextargs.Context{
			MetaInput: &contextargs.MetaInput{
				Input: "http://example.com",
			},
		}

		// Initially not a honeypot
		require.False(t, cache.IsHoneypot(ctx))

		// Record 5 matches (50%)
		for i := 0; i < 5; i++ {
			cache.MarkMatch(ctx, "template-"+string(rune('a'+i)))
		}

		// Should now be detected as honeypot
		require.True(t, cache.IsHoneypot(ctx))
		require.Equal(t, 50.0, cache.GetMatchPercentage(ctx))

		cache.Close()
	})

	t.Run("suppress mode", func(t *testing.T) {
		cache := New(30, true, 100)
		cache.SetTotalTemplates(10)

		ctx := &contextargs.Context{
			MetaInput: &contextargs.MetaInput{
				Input: "http://honeypot.local",
			},
		}

		// Initially should not be checked
		require.False(t, cache.Check(ctx))

		// Record 3 matches (30%)
		for i := 0; i < 3; i++ {
			cache.MarkMatch(ctx, "template-"+string(rune('a'+i)))
		}

		// Should now be suppressed
		require.True(t, cache.Check(ctx))

		cache.Close()
	})

	t.Run("unique template counting", func(t *testing.T) {
		cache := New(50, false, 100)
		cache.SetTotalTemplates(10)

		ctx := &contextargs.Context{
			MetaInput: &contextargs.MetaInput{
				Input: "http://test.com",
			},
		}

		// Record same template multiple times
		cache.MarkMatch(ctx, "template-a")
		cache.MarkMatch(ctx, "template-a")
		cache.MarkMatch(ctx, "template-a")

		// Should only count as 1 match (10%)
		require.Equal(t, 10.0, cache.GetMatchPercentage(ctx))

		cache.Close()
	})

	t.Run("threshold disabled", func(t *testing.T) {
		cache := New(0, false, 100)
		cache.SetTotalTemplates(10)

		ctx := &contextargs.Context{
			MetaInput: &contextargs.MetaInput{
				Input: "http://test.com",
			},
		}

		// Record many matches
		for i := 0; i < 10; i++ {
			cache.MarkMatch(ctx, "template-"+string(rune('a'+i)))
		}

		// Should never be detected as honeypot when threshold is 0
		require.False(t, cache.IsHoneypot(ctx))
		require.False(t, cache.Check(ctx))

		cache.Close()
	})

	t.Run("normalize cache value", func(t *testing.T) {
		cache := New(50, false, 100)

		tests := []struct {
			input    string
			expected string
		}{
			{"http://example.com", "example.com:80"},
			{"https://example.com", "example.com:443"},
			{"http://example.com:8080", "example.com:8080"},
			{"example.com:22", "example.com:22"},
			{"example.com", "example.com"},
		}

		for _, tt := range tests {
			result := cache.NormalizeCacheValue(tt.input)
			require.Equal(t, tt.expected, result, "input: %s", tt.input)
		}

		cache.Close()
	})
}

func TestHoneypotSignatureDetection(t *testing.T) {
	cache := New(50, false, 100)

	tests := []struct {
		name     string
		response string
		detected bool
		sigName  string
	}{
		{
			name:     "cowrie ssh honeypot",
			response: "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
			detected: true,
			sigName:  "Cowrie-SSH",
		},
		{
			name:     "generic honeypot mention",
			response: "Welcome to our honeypot server",
			detected: true,
			sigName:  "Generic-Honeypot",
		},
		{
			name:     "dionaea detection",
			response: "dionaea smb service",
			detected: true,
			sigName:  "Dionaea",
		},
		{
			name:     "normal response",
			response: "HTTP/1.1 200 OK\nServer: nginx/1.18.0",
			detected: false,
			sigName:  "",
		},
		{
			name:     "cowrie keyword",
			response: "Running Cowrie SSH Honeypot",
			detected: true,
			sigName:  "Cowrie",
		},
		{
			name:     "glastopf",
			response: "Glastopf web honeypot",
			detected: true,
			sigName:  "Glastopf",
		},
		{
			name:     "conpot",
			response: "Conpot ICS honeypot",
			detected: true,
			sigName:  "Conpot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detected, sigName := cache.CheckSignature(tt.response)
			require.Equal(t, tt.detected, detected)
			if tt.detected {
				require.Equal(t, tt.sigName, sigName)
			}
		})
	}

	cache.Close()
}
