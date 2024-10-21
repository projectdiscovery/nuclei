package http

import (
	"testing"

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
