package http

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

func TestHttpInputProviderIteratesAllKatanaRecords(t *testing.T) {
	input := `{"request":{"method":"GET","endpoint":"https://example.com/a?id=1"}}` + "\n" +
		`{"request":{"method":"POST","endpoint":"https://example.com/login","body":"user=admin"}}` + "\n" +
		"https://example.com/bare?q=1\n"

	provider, err := NewHttpInputProvider(&HttpMultiFormatOptions{
		InputMode:     "katana",
		InputContents: input,
	})
	require.NoError(t, err)
	require.Equal(t, int64(3), provider.Count())

	var got []string
	provider.Iterate(func(value *contextargs.MetaInput) bool {
		got = append(got, value.Input)
		return true
	})
	require.Equal(t, []string{"https://example.com/a?id=1", "https://example.com/login", "https://example.com/bare?q=1"}, got)

	var first []string
	provider.Iterate(func(value *contextargs.MetaInput) bool {
		first = append(first, value.Input)
		return false
	})
	require.Len(t, first, 1)
}
