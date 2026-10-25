package list

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/targetprofile"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

func TestTargetLines(t *testing.T) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	require.NoError(t, err)
	input := &ListInputProvider{hostMap: hm, ipOptions: &ipOptions{IPV4: true}, profiles: targetprofile.NewRegistry(t.TempDir())}
	defer input.Close()

	lines := strings.Join([]string{
		`{"target": "192.0.2.0/30", "tags": ["tomcat"]}`,
		`{"target": "192.0.2.10", "tags": ["thinkphp"]}`,
		`{"target": "192.0.2.10", "tags": ["tomcat"]}`,
		`192.0.2.20`,
	}, "\n")
	require.NoError(t, input.scanInputFromReader("", strings.NewReader(lines)))

	require.EqualValues(t, 6, input.Count(), "4 CIDR hosts, one merged duplicate, one plain target")
	for _, ip := range []string{"192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.10"} {
		require.NotNil(t, input.profiles.For(&contextargs.MetaInput{Input: ip}), ip)
	}
	require.Nil(t, input.profiles.For(&contextargs.MetaInput{Input: "192.0.2.20"}))
	require.Nil(t, input.profiles.LoadFilter(), "a plain target needs every template")

	err = input.scanInputFromReader("", strings.NewReader(`{"target": "192.0.2.30", "tagz": ["x"]}`))
	require.ErrorContains(t, err, "unknown keys tagz")
}
