package engine

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// chdirTemp moves the test into a fresh working directory and returns it.
func chdirTemp(t *testing.T) string {
	t.Helper()
	cwd := t.TempDir()
	originalWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(cwd))
	t.Cleanup(func() { require.NoError(t, os.Chdir(originalWd)) })
	return cwd
}

// runWithoutLFA opens a test page with local file access off and runs the
// actions on it.
func runWithoutLFA(t *testing.T, actions []*Action) error {
	t.Helper()
	_, err := runWithoutLFAData(t, actions)
	return err
}

// runWithoutLFAData is runWithoutLFA that also returns the action data.
func runWithoutLFAData(t *testing.T, actions []*Action) (ActionData, error) {
	t.Helper()

	// the proxy of the shared browser dials with the empty execution id
	require.NoError(t, protocolstate.Init(&types.Options{}))
	opts := &types.Options{ExecutionId: t.Name(), AllowLocalFileAccess: false}
	require.NoError(t, protocolstate.Init(opts))
	t.Cleanup(func() { protocolstate.Close(opts.ExecutionId) })

	instance, err := sharedBrowser.NewInstance()
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Close() })

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><body>Nuclei Test Page</body></html>`))
	}))
	t.Cleanup(ts.Close)

	input := contextargs.NewWithInput(context.Background(), ts.URL)
	input.CookieJar, err = cookiejar.New(nil)
	require.NoError(t, err)

	actions = append([]*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
	}, actions...)
	data, page, err := instance.Run(input, actions, nil, &Options{Timeout: 20 * time.Second, Options: opts})
	if page != nil {
		page.Close()
	}
	return data, err
}

func screenshotAction(args map[string]string) *Action {
	return &Action{ActionType: ActionTypeHolder{ActionType: ActionScreenshot}, Data: args}
}

func requireNoFiles(t *testing.T, dir string) {
	t.Helper()
	var files []string
	require.NoError(t, filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, path)
		}
		return err
	}))
	require.Empty(t, files, "template wrote into the working directory")
}

func TestScreenshotWithoutLFAWritesOnlyToScreenshotDir(t *testing.T) {
	cwd := chdirTemp(t)
	name := "shot-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	err := runWithoutLFA(t, []*Action{
		screenshotAction(map[string]string{"to": name + "/deep/dir/marker", "mkdir": "true"}),
	})
	require.NoError(t, err)
	requireNoFiles(t, cwd)

	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "nuclei-screenshots-*", name, "deep", "dir", "marker.png"))
	require.NoError(t, err)
	require.Len(t, matches, 1, "screenshot is not in the nuclei screenshot directory")
}

func TestScreenshotWithoutLFANamedResultIsFullPath(t *testing.T) {
	chdirTemp(t)
	action := screenshotAction(map[string]string{})
	action.Name = "shot"
	data, err := runWithoutLFAData(t, []*Action{action})
	require.NoError(t, err)

	path, ok := data["shot"].(string)
	require.True(t, ok)
	require.True(t, filepath.IsAbs(path), "named result %q does not locate the screenshot", path)
	require.FileExists(t, path)
}

func TestScreenshotWithoutLFARejectsPaths(t *testing.T) {
	cases := map[string]func(cwd string) string{
		"absolute inside working directory": func(cwd string) string { return filepath.Join(cwd, "abs") },
		"parent":                            func(string) string { return "../outside" },
		"parent after folder":               func(string) string { return "a/../../outside" },
	}
	for name, to := range cases {
		t.Run(name, func(t *testing.T) {
			cwd := filepath.Join(chdirTemp(t), "work")
			require.NoError(t, os.Mkdir(cwd, 0700))
			require.NoError(t, os.Chdir(cwd))

			err := runWithoutLFA(t, []*Action{screenshotAction(map[string]string{"to": to(cwd), "mkdir": "true"})})
			require.ErrorIs(t, err, ErrLFAccessDenied)
			requireNoFiles(t, filepath.Dir(cwd))
		})
	}
}

func TestScreenshotWithoutLFAIsLimitedPerPage(t *testing.T) {
	chdirTemp(t)
	// one more than the limit of 10 screenshots per page
	actions := make([]*Action, 0, 11)
	for range 11 {
		actions = append(actions, screenshotAction(nil))
	}
	require.ErrorContains(t, runWithoutLFA(t, actions), "screenshot limit", "more screenshots than the limit were written for one page")
}

func TestScreenshotWithoutLFAIsLimitedInSize(t *testing.T) {
	chdirTemp(t)
	noise := `() => { document.body.style.margin='0'; const c=document.createElement('canvas'); c.width=2000; c.height=2000; document.body.appendChild(c); const x=c.getContext('2d'); const d=x.createImageData(2000,2000); for(let i=0;i<d.data.length;i++){d.data[i]=(Math.random()*256)|0; if(i%4==3)d.data[i]=255;} x.putImageData(d,0,0); return 'ok'; }`
	err := runWithoutLFA(t, []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionScript}, Data: map[string]string{"code": noise}},
		screenshotAction(map[string]string{"fullpage": "true"}),
	})
	require.ErrorContains(t, err, "over the limit", "a screenshot over the size limit was written")
}
