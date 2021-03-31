package engine

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/corpix/uarand"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	ps "github.com/mitchellh/go-ps"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Browser is a browser structure for nuclei headless module
type Browser struct {
	customAgent  string
	tempDir      string
	previouspids map[int]struct{} // track already running pids
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
	chromeLauncher := launcher.New().
		Leakless(false).
		Set("disable-gpu", "true").
		Set("ignore-certificate-errors", "true").
		Set("ignore-certificate-errors", "1").
		Set("disable-crash-reporter", "true").
		Set("disable-notifications", "true").
		Set("hide-scrollbars", "true").
		Set("window-size", fmt.Sprintf("%d,%d", 1080, 1920)).
		Set("no-sandbox", "true").
		Set("mute-audio", "true").
		Set("incognito", "true").
		Delete("use-mock-keychain").
		UserDataDir(dataStore)

	if options.ShowBrowser {
		chromeLauncher = chromeLauncher.Headless(false)
	} else {
		chromeLauncher = chromeLauncher.Headless(true)
	}
	if options.ProxyURL != "" {
		chromeLauncher = chromeLauncher.Proxy(options.ProxyURL)
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
	httpclient, err := newhttpClient(options)
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
	engine.previouspids = engine.findChromeProcesses()
	return engine, nil
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
	newProcesses := b.findChromeProcesses()
	for id := range newProcesses {
		if _, ok := b.previouspids[id]; ok {
			continue
		}
		kill(id)
	}
}

// findChromeProcesses finds chrome process running on host
func (b *Browser) findChromeProcesses() map[int]struct{} {
	processes, _ := ps.Processes()
	list := make(map[int]struct{})
	for _, process := range processes {
		if strings.Contains(process.Executable(), "chrome") || strings.Contains(process.Executable(), "chromium") {
			list[process.PPid()] = struct{}{}
			list[process.Pid()] = struct{}{}
		}
	}
	return list
}
