package code

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSeatbeltProfileDeniesHiddenDirsAndNetwork(t *testing.T) {
	profile := seatbeltProfile("/private/var/folders/ws", []string{"/Users", "/private/var/root"})

	require.Contains(t, profile, "(deny network*)")
	require.Contains(t, profile, "(deny file-write*)")
	require.Contains(t, profile, `(subpath "/Users")`)
	require.Contains(t, profile, `(subpath "/private/var/root")`)
	// Seatbelt applies the last matching rule: the workspace re-allow must
	// come after the hidden-dir deny, or a workspace under a hidden dir breaks.
	deny := strings.Index(profile, "(deny file-read* file-write*")
	allow := strings.LastIndex(profile, `(allow file-read* file-write* (subpath "/private/var/folders/ws"))`)
	require.True(t, deny >= 0 && allow > deny, "workspace allow must follow the hidden deny:\n%s", profile)
}

func TestSeatbeltProfileQuotesPaths(t *testing.T) {
	profile := seatbeltProfile(`/tmp/a"b\c`, nil)
	require.Contains(t, profile, `(subpath "/tmp/a\"b\\c")`)
}

func TestBwrapArgsIsolation(t *testing.T) {
	argv := bwrapArgs("/usr/bin/bwrap", "/tmp/ws", []string{"/home", "/run"}, map[string]string{"B": "2", "A": "1"}, []string{"/usr/bin/sh", "/tmp/ws/script"})
	joined := strings.Join(argv, " ")

	require.Equal(t, "/usr/bin/bwrap", argv[0])
	for _, flag := range []string{"--unshare-all", "--die-with-parent", "--new-session", "--clearenv", "--cap-drop ALL", "--ro-bind / /", "--tmpfs /home", "--tmpfs /run", "--bind /tmp/ws /tmp/ws", "--chdir /tmp/ws"} {
		require.Contains(t, joined, flag)
	}
	require.NotContains(t, joined, "--share-net")
	// Later mounts win: the workspace bind must come after the tmpfs mounts.
	require.Less(t, strings.Index(joined, "--tmpfs /home"), strings.Index(joined, "--bind /tmp/ws"))
	require.Less(t, strings.Index(joined, "--bind /tmp/ws"), strings.Index(joined, "--remount-ro /home"))
	require.Contains(t, joined, "--remount-ro /run")
	require.Less(t, strings.Index(joined, "--setenv A 1"), strings.Index(joined, "--setenv B 2"))
	require.Equal(t, []string{"--", "/usr/bin/sh", "/tmp/ws/script"}, argv[len(argv)-3:])
}

func TestNativeEnvScrubsHost(t *testing.T) {
	t.Setenv("NUCLEI_TEST_HOST_SECRET", "leak")
	env := nativeEnv("/tmp/ws", map[string]string{"Target": "x", "bad-key": "y", "HOME": "/override"})

	require.Equal(t, "/tmp/ws", env["HOME"], "template vars must not move HOME out of the workspace")
	require.Equal(t, "/tmp/ws", env["TMPDIR"])
	require.Equal(t, "x", env["Target"])
	require.NotContains(t, env, "bad-key")
	require.NotContains(t, env, "NUCLEI_TEST_HOST_SECRET")
	require.NotEmpty(t, env["PATH"])
}

func TestHiddenDirsDropsNestedAndMissing(t *testing.T) {
	root := t.TempDir()
	dirs := hiddenDirs(root, root+"/missing")
	for _, dir := range dirs {
		require.NotContains(t, dir, "missing")
	}
	for i, a := range dirs {
		for j, b := range dirs {
			if i != j {
				require.False(t, strings.HasPrefix(b, a+"/"), "%s is nested in %s", b, a)
			}
		}
	}
}
