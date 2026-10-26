package list

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/normalize"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/targetprofile"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
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

func TestPinnedTargetLines(t *testing.T) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	require.NoError(t, err)
	// pinned lines never resolve the target, even with -sa
	input := &ListInputProvider{hostMap: hm, ipOptions: &ipOptions{ScanAllIPs: true, IPV4: true}, profiles: targetprofile.NewRegistry(t.TempDir())}
	defer input.Close()

	lines := strings.Join([]string{
		`{"target": "https://a.example", "ip": "192.0.2.10", "tags": ["thinkphp"]}`,
		`{"target": "https://a.example", "ip": "192.0.2.11"}`,
		`{"target": "https://a.example", "ip": "::ffff:192.0.2.11"}`,
	}, "\n")
	require.NoError(t, input.scanInputFromReader("", strings.NewReader(lines)))

	require.True(t, input.PinnedTargets())
	require.EqualValues(t, 2, input.Count(), "the IPv4-mapped ip is a duplicate")
	var got []string
	input.Iterate(func(value *contextargs.MetaInput) bool {
		got = append(got, value.Input+" "+value.CustomIP)
		return true
	})
	require.ElementsMatch(t, []string{"https://a.example 192.0.2.10", "https://a.example 192.0.2.11"}, got)
	require.NotNil(t, input.profiles.For(&contextargs.MetaInput{Input: "https://a.example", CustomIP: "192.0.2.10"}))
	require.Nil(t, input.profiles.For(&contextargs.MetaInput{Input: "https://a.example", CustomIP: "192.0.2.11"}))
}

func TestPinnedTargetLinesKeepEveryIPUnderPatternCap(t *testing.T) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	require.NoError(t, err)
	// -mup 1
	input := &ListInputProvider{hostMap: hm, ipOptions: &ipOptions{IPV4: true}, profiles: targetprofile.NewRegistry(t.TempDir()), patterns: normalize.NewFingerprinter(1)}
	defer input.Close()

	lines := strings.Join([]string{
		`{"target": "https://a.example/user/1", "ip": "192.0.2.10"}`,
		`{"target": "https://a.example/user/1", "ip": "192.0.2.11"}`,
		`{"target": "https://a.example/user/2", "ip": "192.0.2.10"}`,
	}, "\n")
	require.NoError(t, input.scanInputFromReader("", strings.NewReader(lines)))

	var got []string
	input.Iterate(func(value *contextargs.MetaInput) bool {
		got = append(got, value.Input+" "+value.CustomIP)
		return true
	})
	require.ElementsMatch(t, []string{"https://a.example/user/1 192.0.2.10", "https://a.example/user/1 192.0.2.11"}, got)
	require.EqualValues(t, 1, input.patternSkippedCount, "user/2 has the shape of user/1 on the same ip")
}

func TestPinnedTargetLinesFollowNetworkPolicy(t *testing.T) {
	options := types.DefaultOptions()
	options.ExecutionId = "pinned-target-lines"
	options.ExcludeTargets = []string{"192.0.2.0/28"}
	require.NoError(t, protocolstate.Init(options))
	t.Cleanup(func() { protocolstate.Close(options.ExecutionId) })

	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	require.NoError(t, err)
	input := &ListInputProvider{hostMap: hm, ipOptions: &ipOptions{IPV4: true}, profiles: targetprofile.NewRegistry(t.TempDir())}
	defer input.Close()

	lines := strings.Join([]string{
		`{"target": "https://a.example", "ip": "192.0.2.10"}`,
		`{"target": "https://a.example", "ip": "192.0.2.20"}`,
	}, "\n")
	require.NoError(t, input.scanInputFromReader(options.ExecutionId, strings.NewReader(lines)))

	require.EqualValues(t, 1, input.Count())
	require.EqualValues(t, 1, input.skippedCount, "the excluded ip is skipped")
}
