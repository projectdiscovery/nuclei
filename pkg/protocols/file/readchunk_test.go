package file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
)

var tinyPNG = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

func TestReadChunkShortFile(t *testing.T) {
	dir := t.TempDir()

	small := filepath.Join(dir, "tiny.png")
	require.NoError(t, os.WriteFile(small, tinyPNG, 0o600))
	got, err := readChunk(small)
	require.NoError(t, err)
	require.Equal(t, tinyPNG, got)

	empty := filepath.Join(dir, "empty")
	require.NoError(t, os.WriteFile(empty, nil, 0o600))
	got, err = readChunk(empty)
	require.NoError(t, err)
	require.Empty(t, got)

	big := filepath.Join(dir, "big.bin")
	require.NoError(t, os.WriteFile(big, append(append([]byte{}, tinyPNG...), make([]byte, 4096)...), 0o600))
	got, err = readChunk(big)
	require.NoError(t, err)
	require.Len(t, got, 1024)

	_, err = readChunk(filepath.Join(dir, "missing"))
	require.Error(t, err)
}

func TestValidatePathDenyMimeTypeShortFile(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)
	templateID := "testing-file-mime"
	request := &Request{
		ID:         templateID,
		MaxSize:    "1Gb",
		MimeType:   true,
		Extensions: []string{"all"},
		DenyList:   []string{"image/png"},
		Operators:  newMockOperator(),
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOpts))

	dir := t.TempDir()
	png := filepath.Join(dir, "tiny.dat")
	require.NoError(t, os.WriteFile(png, tinyPNG, 0o600))
	bigPNG := filepath.Join(dir, "big.dat")
	require.NoError(t, os.WriteFile(bigPNG, append(append([]byte{}, tinyPNG...), make([]byte, 4096)...), 0o600))
	text := filepath.Join(dir, "note.dat")
	require.NoError(t, os.WriteFile(text, []byte("hello"), 0o600))

	require.False(t, request.validatePath(dir, png, false), "short png must be excluded by the image/png deny entry")
	require.False(t, request.validatePath(dir, bigPNG, false), "large png must be excluded by the image/png deny entry")
	require.True(t, request.validatePath(dir, text, false))
}
