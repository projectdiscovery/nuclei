package runner

import (
	"fmt"
	"io"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
)

type directoryRecord struct {
	label string
	path  string
}

func directoryRecords() []directoryRecord {
	return []directoryRecord{
		{label: "Nuclei Config Directory", path: config.DefaultConfig.GetConfigDir()},
		{label: "Nuclei State Directory", path: config.DefaultConfig.GetStateDir()},
		{label: "Nuclei Cache Directory", path: config.DefaultConfig.GetCacheDir()},
		{label: "PDCP Directory", path: pdcpauth.PDCPDir},
	}
}

// AppendDirectoryInfo writes nuclei config/state/cache/PDCP directory paths.
func AppendDirectoryInfo(w io.Writer) {
	for _, record := range directoryRecords() {
		_, _ = fmt.Fprintf(w, "%s: %s\n", record.label, record.path)
	}
}

// DirectoryInfo returns nuclei config/state/cache/PDCP directory paths as a string.
func DirectoryInfo() string {
	var b strings.Builder

	AppendDirectoryInfo(&b)

	return b.String()
}

// LogDirectoryInfo logs nuclei config/state/cache/PDCP directory paths at info level.
func LogDirectoryInfo(logger *gologger.Logger) {
	if logger == nil {
		return
	}

	for _, record := range directoryRecords() {
		logger.Info().Msgf("%s: %s", record.label, record.path)
	}
}
