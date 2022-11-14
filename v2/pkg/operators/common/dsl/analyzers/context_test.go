package analyzers

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnalyze(t *testing.T) {
	dir := "/Users/ice3man/projectdiscovery/nuclei/v2/cmd/nuclei/output"
	files, err := os.ReadDir(dir)
	require.NoError(t, err, "could not read dir")

	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		require.NoError(t, err, "could not read response")

		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
		require.NoError(t, err, "could not parse response")

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		AnalyzeHTMLContext("6842", "", "8864", string(body))
	}
}
