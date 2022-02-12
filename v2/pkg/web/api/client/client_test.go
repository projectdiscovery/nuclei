package client

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	client := New(WithBasicAuth("user", "pass"))
	require.NotNil(t, client)
}
