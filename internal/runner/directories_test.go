package runner

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
)

func TestDirectoryInfoContainsKnownLabels(t *testing.T) {
	info := DirectoryInfo()
	cfg := config.DefaultConfig

	require.Equal(t, strings.Join([]string{
		fmt.Sprintf("Nuclei Config Directory: %s", cfg.GetConfigDir()),
		fmt.Sprintf("Nuclei Cache Directory: %s", cfg.GetCacheDir()),
		fmt.Sprintf("PDCP Directory: %s", pdcpauth.PDCPDir),
		"",
	}, "\n"), info)
	require.Equal(t, 3, strings.Count(info, "\n"))
}
