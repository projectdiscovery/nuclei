package engine

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
	osutils "github.com/projectdiscovery/utils/os"
	processutil "github.com/projectdiscovery/utils/process"
)

// Browser is a browser structure for nuclei headless module
type Browser struct {
	customAgent  string
	tempDir      string
	previousPIDs map[int32]struct{} // track already running PIDs
	engine       *rod.Browser
	options      *types.Options
	// use getHTTPClient to get the http client
	httpClient     *http.Client
	httpClientOnce *sync.Once
}

// New creates a new nuclei headless browser module
func New(options *types.Options) (*Browser, error) {
	dataStore, err := os.MkdirTemp("", "nuclei-*")
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary directory")
	}
	previousPIDs := processutil.FindProcesses(processutil.IsChromeProcess)

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

	executablePath, err := os.Executable()
	if err != nil {
		return nil, err
	}

	// if musl is used, most likely we are on alpine linux which is not supported by go-rod, so we fallback to default chrome
	useMusl, _ := fileutil.UseMusl(executablePath)
	if options.UseInstalledChrome || useMusl {
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
	if options.AliveHttpProxy != "" {
		chromeLauncher = chromeLauncher.Proxy(options.AliveHttpProxy)
	}

	for k, v := range options.ParseHeadlessOptionalArguments() {
		chromeLauncher.Set(flags.Flag(k), v)
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

	engine := &Browser{
		tempDir:        dataStore,
		customAgent:    customAgent,
		engine:         browser,
		options:        options,
		httpClientOnce: &sync.Once{},
	}
	engine.previousPIDs = previousPIDs
	return engine, nil
}

// MustDisableSandbox determines if the current os and user needs sandbox mode disabled
func MustDisableSandbox() bool {
	// linux with root user needs "--no-sandbox" option
	// https://github.com/chromium/chromium/blob/c4d3c31083a2e1481253ff2d24298a1dfe19c754/chrome/test/chromedriver/client/chromedriver.py#L209
	return osutils.IsLinux()
}

// SetUserAgent sets custom user agent to the browser
func (b *Browser) SetUserAgent(customUserAgent string) {
	b.customAgent = customUserAgent
}

// UserAgent fetch the currently set custom user agent
func (b *Browser) UserAgent() string {
	return b.customAgent
}

func (b *Browser) getHTTPClient() (*http.Client, error) {
	var err error
	b.httpClientOnce.Do(func() {
		b.httpClient, err = newHttpClient(b.options)
	})
	return b.httpClient, err
}

// Close closes the browser engine
func (b *Browser) Close() {
	b.engine.Close()
	os.RemoveAll(b.tempDir)
	processutil.CloseProcesses(processutil.IsChromeProcess, b.previousPIDs)
}
