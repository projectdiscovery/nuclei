package tsdocs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEntityParser(t *testing.T) {
	value := "../../libs/ssh/ssh.go"
	parser, err := NewEntityParser(value)
	require.Nil(t, err, "could not create parser")
	require.NotNil(t, parser, "could not create parser")

	err = parser.Parse()
	require.Nil(t, err, "could not parse file")

	t.Log(parser.entities)
}
