package templates

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {
	templates := NewCache()
	testErr := errors.New("test error")

	data, _, err := templates.Has("test")
	require.Nil(t, err, "invalid value for err")
	require.Nil(t, data, "invalid value for data")

	item := &Template{}

	templates.Store("test", item, nil, testErr)
	data, _, err = templates.Has("test")
	require.Equal(t, testErr, err, "invalid value for err")
	require.Equal(t, item, data, "invalid value for data")
}
