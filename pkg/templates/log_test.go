package templates

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_appendAtSignToAuthors(t *testing.T) {
	result := appendAtSignToAuthors([]string{"user1", "user2", "user3"})
	assert.Equal(t, result, "@user1,@user2,@user3")
}

func Test_appendAtSignToMissingAuthors(t *testing.T) {
	result := appendAtSignToAuthors([]string{})
	assert.Equal(t, result, "@none")

	result = appendAtSignToAuthors(nil)
	assert.Equal(t, result, "@none")
}

func Test_appendAtSignToOneAuthor(t *testing.T) {
	result := appendAtSignToAuthors([]string{"user1"})
	assert.Equal(t, result, "@user1")
}
