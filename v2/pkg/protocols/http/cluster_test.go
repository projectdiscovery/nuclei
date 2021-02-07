package http

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanCluster(t *testing.T) {
	req := &Request{Unsafe: true}
	require.False(t, req.CanCluster(&Request{}), "could cluster unsafe request")

	req = &Request{Path: []string{"{{BaseURL}}"}, Method: "GET"}
	require.True(t, req.CanCluster(&Request{Path: []string{"{{BaseURL}}"}, Method: "GET"}), "could not cluster GET request")
}
