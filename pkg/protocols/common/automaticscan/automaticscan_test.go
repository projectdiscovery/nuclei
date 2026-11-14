package automaticscan

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeAppName(t *testing.T) {
	appName := normalizeAppName("JBoss")
	require.Equal(t, "jboss", appName, "could not get normalized name")

	appName = normalizeAppName("JBoss:2.3.5")
	require.Equal(t, "jboss", appName, "could not get normalized name")
}

func TestCategoryFromPath(t *testing.T) {
	require.Equal(t, "cves", categoryFromPath("/home/templates/http/cves/2024/CVE-2024-1.yaml"))
	require.Equal(t, "fuzzing", categoryFromPath("http/fuzzing/xss.yaml"))
	require.Equal(t, "", categoryFromPath("README.md"))
}
