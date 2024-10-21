package templates

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_appendAtSignToAuthors(t *testing.T) {
	result := appendAtSignToAuthors([]string{"user1", "user2", "user3"})
	require.Equal(t, result, "@user1,@user2,@user3")
}

func Test_appendAtSignToMissingAuthors(t *testing.T) {
	result := appendAtSignToAuthors([]string{})
	require.Equal(t, result, "@none")

	result = appendAtSignToAuthors(nil)
	require.Equal(t, result, "@none")
}

func Test_appendAtSignToOneAuthor(t *testing.T) {
	result := appendAtSignToAuthors([]string{"user1"})
	require.Equal(t, result, "@user1")
}
