package utils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnwrapError(t *testing.T) {
	require.Equal(t, nil, UnwrapError(nil))

	errOne := fmt.Errorf("error one")
	require.Equal(t, errOne, UnwrapError(errOne))

	errTwo := fmt.Errorf("error with error: %w", errOne)
	require.Equal(t, errOne, UnwrapError(errTwo))

	errThree := fmt.Errorf("error with error: %w", errTwo)
	require.Equal(t, errOne, UnwrapError(errThree))
}
