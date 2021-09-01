package cache

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {
	templates := New()
	testErr := errors.New("test error")

	data, err := templates.Has("test")
	require.Nil(t, err, "invalid value for err")
	require.Nil(t, data, "invalid value for data")

	templates.Store("test", "data", testErr)
	data, err = templates.Has("test")
	require.Equal(t, testErr, err, "invalid value for err")
	require.Equal(t, "data", data, "invalid value for data")
}
