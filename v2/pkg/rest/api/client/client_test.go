package client

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	client := New(WithToken("test"))
	require.NotNil(t, client)
}
