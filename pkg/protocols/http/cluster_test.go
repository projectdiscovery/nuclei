package http

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/stretchr/testify/require"
)

func TestCanCluster(t *testing.T) {
	req := &Request{Unsafe: true}
	require.False(t, req.IsClusterable(), "could cluster unsafe request")

	req = &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}}
	newReq := &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}}
	require.True(t, req.IsClusterable(), "could not cluster GET request")
	require.True(t, req.IsClusterable(), "could not cluster GET request")
	require.Equal(t, req.TmplClusterKey(), newReq.TmplClusterKey(), "cluster keys should be equal")
}

func TestIsClusterable(t *testing.T) {
	t.Run("simple GET is clusterable", func(t *testing.T) {
		req := &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}}
		require.True(t, req.IsClusterable())
	})

	t.Run("payloads prevent clustering", func(t *testing.T) {
		req := &Request{
			Path:     []string{"{{BaseURL}}"},
			Method:   HTTPMethodTypeHolder{MethodType: HTTPGet},
			Payloads: map[string]interface{}{"user": "admin"},
		}
		require.False(t, req.IsClusterable())
	})

	t.Run("fuzzing prevents clustering", func(t *testing.T) {
		req := &Request{
			Path:    []string{"{{BaseURL}}"},
			Method:  HTTPMethodTypeHolder{MethodType: HTTPGet},
			Fuzzing: []*fuzz.Rule{{}},
		}
		require.False(t, req.IsClusterable())
	})

	t.Run("raw requests prevent clustering", func(t *testing.T) {
		req := &Request{
			Raw: []string{"GET / HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"},
		}
		require.False(t, req.IsClusterable())
	})

	t.Run("body prevents clustering", func(t *testing.T) {
		req := &Request{
			Path:   []string{"{{BaseURL}}"},
			Method: HTTPMethodTypeHolder{MethodType: HTTPPost},
			Body:   "key=value",
		}
		require.False(t, req.IsClusterable())
	})

	t.Run("unsafe prevents clustering", func(t *testing.T) {
		req := &Request{Unsafe: true, Raw: []string{"GET / HTTP/1.1\r\n\r\n"}}
		require.False(t, req.IsClusterable())
	})

	t.Run("named request prevents clustering", func(t *testing.T) {
		req := &Request{
			Path:   []string{"{{BaseURL}}"},
			Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
			Name:   "login-check",
		}
		require.False(t, req.IsClusterable())
	})

	t.Run("redirects do not prevent clustering", func(t *testing.T) {
		req := &Request{
			Path:      []string{"{{BaseURL}}"},
			Method:    HTTPMethodTypeHolder{MethodType: HTTPGet},
			Redirects: true,
		}
		require.True(t, req.IsClusterable())
	})

	t.Run("protocol-redirects do not prevent clustering", func(t *testing.T) {
		req := &Request{
			Path:              []string{"{{BaseURL}}"},
			Method:            HTTPMethodTypeHolder{MethodType: HTTPGet},
			Redirects:         true,
			ProtocolRedirects: true,
		}
		require.True(t, req.IsClusterable())
	})
}

func TestTmplClusterKeyIdempotent(t *testing.T) {
	req := &Request{
		Path:         []string{"{{BaseURL}}/admin"},
		Method:       HTTPMethodTypeHolder{MethodType: HTTPGet},
		MaxRedirects: 5,
		Redirects:    true,
		Headers:      map[string]string{"X-Custom": "test"},
	}
	key1 := req.TmplClusterKey()
	key2 := req.TmplClusterKey()
	require.Equal(t, key1, key2, "cluster key should be deterministic")
}

func TestTmplClusterKeyIdenticalRequests(t *testing.T) {
	make := func() *Request {
		return &Request{
			Path:          []string{"{{BaseURL}}"},
			Method:        HTTPMethodTypeHolder{MethodType: HTTPGet},
			MaxRedirects:  3,
			DisableCookie: true,
			Redirects:     true,
			Headers:       map[string]string{"Accept": "text/html"},
		}
	}
	require.Equal(t, make().TmplClusterKey(), make().TmplClusterKey())
}

func TestTmplClusterKeyDiffersOnMethod(t *testing.T) {
	base := &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}}
	other := &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPPost}}
	require.NotEqual(t, base.TmplClusterKey(), other.TmplClusterKey())
}

func TestTmplClusterKeyDiffersOnMaxRedirects(t *testing.T) {
	base := &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}, MaxRedirects: 5}
	other := &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}, MaxRedirects: 10}
	require.NotEqual(t, base.TmplClusterKey(), other.TmplClusterKey())
}

func TestTmplClusterKeyDiffersOnDisableCookie(t *testing.T) {
	base := &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}, DisableCookie: false}
	other := &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}, DisableCookie: true}
	require.NotEqual(t, base.TmplClusterKey(), other.TmplClusterKey())
}

func TestTmplClusterKeyDiffersOnRedirects(t *testing.T) {
	base := &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}, Redirects: false}
	other := &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}, Redirects: true}
	require.NotEqual(t, base.TmplClusterKey(), other.TmplClusterKey())
}

func TestTmplClusterKeyDiffersOnProtocolRedirects(t *testing.T) {
	base := &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}, Redirects: true}
	withProto := &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}, Redirects: true, ProtocolRedirects: true}
	require.NotEqual(t, base.TmplClusterKey(), withProto.TmplClusterKey())
}

func TestTmplClusterKeyDiffersOnPath(t *testing.T) {
	base := &Request{Path: []string{"{{BaseURL}}/a"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}}
	other := &Request{Path: []string{"{{BaseURL}}/b"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}}
	require.NotEqual(t, base.TmplClusterKey(), other.TmplClusterKey())
}

func TestTmplClusterKeyDiffersOnMultiplePaths(t *testing.T) {
	base := &Request{Path: []string{"{{BaseURL}}/a", "{{BaseURL}}/b"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}}
	other := &Request{Path: []string{"{{BaseURL}}/a", "{{BaseURL}}/c"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}}
	require.NotEqual(t, base.TmplClusterKey(), other.TmplClusterKey())
}

func TestTmplClusterKeyDiffersOnHeaders(t *testing.T) {
	base := &Request{
		Path:    []string{"{{BaseURL}}"},
		Method:  HTTPMethodTypeHolder{MethodType: HTTPGet},
		Headers: map[string]string{"X-Test": "a"},
	}
	other := &Request{
		Path:    []string{"{{BaseURL}}"},
		Method:  HTTPMethodTypeHolder{MethodType: HTTPGet},
		Headers: map[string]string{"X-Test": "b"},
	}
	require.NotEqual(t, base.TmplClusterKey(), other.TmplClusterKey())
}

func TestTmplClusterKeyNilVsEmptyHeaders(t *testing.T) {
	noHeaders := &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}}
	emptyHeaders := &Request{Path: []string{"{{BaseURL}}"}, Method: HTTPMethodTypeHolder{MethodType: HTTPGet}, Headers: map[string]string{}}
	require.Equal(t, noHeaders.TmplClusterKey(), emptyHeaders.TmplClusterKey(), "nil and empty headers should produce the same key")
}

func TestIsClusterableWithReqCondition(t *testing.T) {
	req := &Request{
		Path:   []string{"{{BaseURL}}"},
		Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{
				{DSL: []string{"status_code_1 == 200"}},
			},
		},
	}
	require.False(t, req.IsClusterable(), "request with req-condition matchers should not be clusterable")
}
