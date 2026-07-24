package runner

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDirectoryInfoContainsKnownLabels(t *testing.T) {
	info := DirectoryInfo()
	require.Contains(t, info, "Nuclei Config Directory:")
	require.Contains(t, info, "Nuclei Cache Directory:")
	require.Contains(t, info, "PDCP Directory:")
	require.Equal(t, 3, strings.Count(info, "\n"))
}

func TestDoHealthCheckIncludesDirectoryInfo(t *testing.T) {
	out := DoHealthCheck(nil)
	require.Contains(t, out, "Nuclei Config Directory:")
	require.Contains(t, out, "Nuclei Cache Directory:")
	require.Contains(t, out, "PDCP Directory:")
}
