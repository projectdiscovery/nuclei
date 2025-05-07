package dedupe

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func TestDedupeDuplicates(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "nuclei")
	require.Nil(t, err, "could not create temporary storage")
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	storage, err := New(tempDir)
	require.Nil(t, err, "could not create duplicate storage")

	tests := []*output.ResultEvent{
		{TemplateID: "test", Host: "https://example.com"},
		{TemplateID: "test", Host: "https://example.com"},
	}
	first, err := storage.Index(tests[0])
	require.Nil(t, err, "could not index item")
	require.True(t, first, "could not index valid item")

	second, err := storage.Index(tests[1])
	require.Nil(t, err, "could not index item")
	require.False(t, second, "could index duplicate item")
}
