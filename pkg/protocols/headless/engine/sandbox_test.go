package engine

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestMustDisableSandbox(t *testing.T) {
	require.Equal(t, runtime.GOOS == "linux" && os.Geteuid() == 0, MustDisableSandbox(), "only root on linux runs the browser without sandbox")

	require.True(t, mustDisableSandbox(true, 0))
	require.False(t, mustDisableSandbox(true, 1000))
	require.False(t, mustDisableSandbox(false, 0))
	require.False(t, mustDisableSandbox(false, 1000))
}

func TestNewChromeLauncherSandboxFlag(t *testing.T) {
	options := &types.Options{}

	sandboxed, err := newChromeLauncher(options, t.TempDir(), "127.0.0.1:1", false)
	require.NoError(t, err)
	require.False(t, sandboxed.Has(flags.NoSandbox), "the sandbox must stay on, also inside containers")

	unsandboxed, err := newChromeLauncher(options, t.TempDir(), "127.0.0.1:1", true)
	require.NoError(t, err)
	require.True(t, unsandboxed.Has(flags.NoSandbox))

	options.HeadlessOptionalArguments = []string{"no-sandbox=true"}
	override, err := newChromeLauncher(options, t.TempDir(), "127.0.0.1:1", false)
	require.NoError(t, err)
	require.True(t, override.Has(flags.NoSandbox), "-headless-options must still disable the sandbox")
}

func TestIsSandboxLaunchError(t *testing.T) {
	err := errors.New("[launcher] Failed to get the debug url: \n[1:1:FATAL:zygote_host_impl_linux.cc(128)] No usable sandbox! If you are running on Ubuntu 23.10+ ...")
	require.True(t, isSandboxLaunchError(err))
	require.Equal(t, "[1:1:FATAL:zygote_host_impl_linux.cc(128)] No usable sandbox! If you are running on Ubuntu 23.10+ ...", sandboxLine(err.Error()))
	require.False(t, isSandboxLaunchError(errors.New("the chrome browser is not installed")))
	require.False(t, isSandboxLaunchError(nil))
}

func stubBrowserDiscovery(t *testing.T, windowsARM64 bool, path string, found bool) {
	t.Helper()
	oldLookPath, oldWindowsARM64 := lookPath, isWindowsARM64
	t.Cleanup(func() { lookPath, isWindowsARM64 = oldLookPath, oldWindowsARM64 })
	isWindowsARM64 = windowsARM64
	lookPath = func() (string, bool) { return path, found }
}

func TestNewChromeLauncherWindowsARM64Bin(t *testing.T) {
	const installed = `C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe`

	t.Run("sets the installed browser when found", func(t *testing.T) {
		stubBrowserDiscovery(t, true, installed, true)
		l, err := newChromeLauncher(&types.Options{}, t.TempDir(), "127.0.0.1:1", false)
		require.NoError(t, err)
		require.Equal(t, installed, l.Get(flags.Bin))
	})

	t.Run("rod-bin option wins", func(t *testing.T) {
		stubBrowserDiscovery(t, true, installed, true)
		options := &types.Options{HeadlessOptionalArguments: []string{"rod-bin=custom-browser"}}
		l, err := newChromeLauncher(options, t.TempDir(), "127.0.0.1:1", false)
		require.NoError(t, err)
		require.Equal(t, "custom-browser", l.Get(flags.Bin))
	})

	t.Run("not found keeps the previous behavior", func(t *testing.T) {
		stubBrowserDiscovery(t, true, "", false)
		l, err := newChromeLauncher(&types.Options{}, t.TempDir(), "127.0.0.1:1", false)
		require.NoError(t, err)
		require.Empty(t, l.Get(flags.Bin), "bin must stay unset so rod resolves it as before")
	})

	t.Run("other platforms never look up the browser", func(t *testing.T) {
		stubBrowserDiscovery(t, false, installed, true)
		lookPath = func() (string, bool) {
			t.Fatal("browser discovery must not run on other platforms")
			return "", false
		}
		l, err := newChromeLauncher(&types.Options{}, t.TempDir(), "127.0.0.1:1", false)
		require.NoError(t, err)
		require.Empty(t, l.Get(flags.Bin))
	})
}
