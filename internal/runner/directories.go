package runner

import (
	"fmt"
	"io"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
)

// AppendDirectoryInfo writes nuclei config/cache/PDCP directory paths.
func AppendDirectoryInfo(w io.Writer) {
	_, _ = fmt.Fprintf(w, "Nuclei Config Directory: %s\n", config.DefaultConfig.GetConfigDir())
	_, _ = fmt.Fprintf(w, "Nuclei Cache Directory: %s\n", config.DefaultConfig.GetCacheDir())
	_, _ = fmt.Fprintf(w, "PDCP Directory: %s\n", pdcpauth.PDCPDir)
}

// DirectoryInfo returns nuclei config/cache/PDCP directory paths as a string.
func DirectoryInfo() string {
	var b strings.Builder
	AppendDirectoryInfo(&b)
	return b.String()
}

// LogDirectoryInfo logs nuclei config/cache/PDCP directory paths at info level.
func LogDirectoryInfo(logger *gologger.Logger) {
	if logger == nil {
		return
	}
	logger.Info().Msgf("Nuclei Config Directory: %s", config.DefaultConfig.GetConfigDir())
	logger.Info().Msgf("Nuclei Cache Directory: %s", config.DefaultConfig.GetCacheDir())
	logger.Info().Msgf("PDCP Directory: %s", pdcpauth.PDCPDir)
}
