package catalog

import (
	"fmt"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
	"github.com/stretchr/testify/require"
)

func TestIgnoreFilesIgnore(t *testing.T) {
	gologger.DefaultLogger.SetWriter(&testutils.NoopWriter{})

	c := &Catalog{
		ignoreFiles:        []string{"workflows/", "cves/2020/cve-2020-5432.yaml"},
		templatesDirectory: "test",
	}
	tests := []struct {
		path   string
		ignore bool
	}{
		{"workflows/", true},
		{"misc", false},
		{"cves/", false},
		{"cves/2020/cve-2020-5432.yaml", true},
		{"/Users/test/nuclei-templates/workflows/", true},
		{"/Users/test/nuclei-templates/misc", false},
		{"/Users/test/nuclei-templates/cves/", false},
		{"/Users/test/nuclei-templates/cves/2020/cve-2020-5432.yaml", true},
	}
	for _, test := range tests {
		require.Equal(t, test.ignore, c.checkIfInNucleiIgnore(test.path), fmt.Sprintf("could not ignore file correctly: %v", test))
	}
}

func TestExcludeFilesIgnore(t *testing.T) {
	c := &Catalog{}
	excludes := []string{"workflows/", "cves/2020/cve-2020-5432.yaml"}
	paths := []string{"/Users/test/nuclei-templates/workflows/", "/Users/test/nuclei-templates/cves/2020/cve-2020-5432.yaml", "/Users/test/nuclei-templates/workflows/test-workflow.yaml", "/Users/test/nuclei-templates/cves/"}

	data := c.ignoreFilesWithExcludes(paths, excludes)
	require.Equal(t, []string{"/Users/test/nuclei-templates/workflows/test-workflow.yaml", "/Users/test/nuclei-templates/cves/"}, data, "could not exclude correct files")
}
