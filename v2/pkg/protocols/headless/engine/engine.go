package engine

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/corpix/uarand"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/pkg/errors"
	ps "github.com/shirou/gopsutil/v3/process"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/stringsutil"
)

// Browser is a browser structure for nuclei headless module
type Browser struct {
	customAgent  string
	tempDir      string
	previousPIDs map[int32]struct{} // track already running PIDs
	engine       *rod.Browser
	httpclient   *http.Client
	options      *types.Options
}

// New creates a new nuclei headless browser module
func New(options *types.Options) (*Browser, error) {
	dataStore, err := ioutil.TempDir("", "nuclei-*")
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary directory")
	}
	previousPIDs := findChromeProcesses()

	chromeLauncher := launcher.New().
		Leakless(false).
		Set("disable-gpu", "true").
		Set("ignore-certificate-errors", "true").
		Set("ignore-certificate-errors", "1").
		Set("disable-crash-reporter", "true").
		Set("disable-notifications", "true").
		Set("hide-scrollbars", "true").
		Set("window-size", fmt.Sprintf("%d,%d", 1080, 1920)).
		Set("mute-audio", "true").
		Set("incognito", "true").
		Delete("use-mock-keychain").
		UserDataDir(dataStore)

	if MustDisableSandbox() {
		chromeLauncher = chromeLauncher.NoSandbox(true)
	}

	if options.UseInstalledChrome {
		if chromePath, hasChrome := launcher.LookPath(); hasChrome {
			chromeLauncher.Bin(chromePath)
		} else {
			return nil, errors.New("the chrome browser is not installed")
		}
	}

	if options.ShowBrowser {
		chromeLauncher = chromeLauncher.Headless(false)
	} else {
		chromeLauncher = chromeLauncher.Headless(true)
	}
	if types.ProxyURL != "" {
		chromeLauncher = chromeLauncher.Proxy(types.ProxyURL)
	}
	launcherURL, err := chromeLauncher.Launch()
	if err != nil {
		return nil, err
	}

	browser := rod.New().ControlURL(launcherURL)
	if browserErr := browser.Connect(); browserErr != nil {
		return nil, browserErr
	}
	customAgent := ""
	for _, option := range options.CustomHeaders {
		parts := strings.SplitN(option, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(parts[0], "User-Agent") {
			customAgent = parts[1]
		}
	}
	if customAgent == "" {
		customAgent = uarand.GetRandom()
	}

	httpclient, err := newHttpClient(options)
	if err != nil {
		return nil, err
	}

	engine := &Browser{
		tempDir:     dataStore,
		customAgent: customAgent,
		engine:      browser,
		httpclient:  httpclient,
		options:     options,
	}
	engine.previousPIDs = previousPIDs
	return engine, nil
}

// MustDisableSandbox determines if the current os and user needs sandbox mode disabled
func MustDisableSandbox() bool {
	// linux with root user needs "--no-sandbox" option
	// https://github.com/chromium/chromium/blob/c4d3c31083a2e1481253ff2d24298a1dfe19c754/chrome/test/chromedriver/client/chromedriver.py#L209
	return runtime.GOOS == "linux" && os.Geteuid() == 0
}

// Close closes the browser engine
func (b *Browser) Close() {
	b.engine.Close()
	os.RemoveAll(b.tempDir)
	b.killChromeProcesses()
}

// killChromeProcesses any and all new chrome processes started after
// headless process launch.
func (b *Browser) killChromeProcesses() {
	processes, _ := ps.Processes()

	for _, process := range processes {
		// skip non-chrome processes
		if !isChromeProcess(process) {
			continue
		}
		// skip chrome processes that were already running
		if _, ok := b.previousPIDs[process.Pid]; ok {
			continue
		}
		_ = process.Kill()
	}
}

// findChromeProcesses finds chrome process running on host
func findChromeProcesses() map[int32]struct{} {
	processes, _ := ps.Processes()
	list := make(map[int32]struct{})
	for _, process := range processes {
		if isChromeProcess(process) {
			list[process.Pid] = struct{}{}
			if ppid, err := process.Ppid(); err == nil {
				list[ppid] = struct{}{}
			}
		}
	}
	return list
}

// isChromeProcess checks if a process is chrome/chromium
func isChromeProcess(process *ps.Process) bool {
	name, _ := process.Name()
	executable, _ := process.Exe()
	return stringsutil.ContainsAny(name, "chrome", "chromium") || stringsutil.ContainsAny(executable, "chrome", "chromium")
}
