package engine

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/utils/chromeshell"
	fileutil "github.com/projectdiscovery/utils/file"
	osutils "github.com/projectdiscovery/utils/os"
)

// Browser is a browser structure for nuclei headless module
type Browser struct {
	customAgent    string
	defaultHeaders map[string]string
	tempDir        string
	engine         *rod.Browser
	options        *types.Options
	launcher       *launcher.Launcher
	proxy          *headlessProxy

	// use getHTTPClient to get the http client
	httpClient     *http.Client
	httpClientOnce *sync.Once
}

// New creates a new nuclei headless browser module
func New(options *types.Options) (*Browser, error) {
	var launcherURL, dataStore string
	var proxyServer *headlessProxy
	var err error

	var chromeLauncher *launcher.Launcher

	if options.CDPEndpoint == "" {
		dataStore, err = os.MkdirTemp("", "nuclei-*")
		if err != nil {
			return nil, errors.Wrap(err, "could not create temporary directory")
		}

		newChromeLauncher := func(browserPath string) *launcher.Launcher {
			configured := launcher.New().
				Leakless(false).
				Set("disable-crash-reporter").
				Set("disable-gpu").
				Set("disable-notifications").
				Set("hide-scrollbars").
				Set("ignore-certificate-errors").
				Set("ignore-ssl-errors").
				Set("incognito").
				Set("mute-audio").
				Set("window-size", fmt.Sprintf("%d,%d", 1080, 1920)).
				Delete("use-mock-keychain").
				UserDataDir(dataStore)

			if browserPath != "" {
				configured.Bin(browserPath)
			}
			if MustDisableSandbox() {
				configured.NoSandbox(true)
			}
			configured.Headless(!options.ShowBrowser)
			configured.
				Proxy(proxyServer.Addr()).
				Set("proxy-bypass-list", "<-loopback>")
			for k, v := range options.ParseHeadlessOptionalArguments() {
				configured.Set(flags.Flag(k), v)
			}
			return configured
		}

		browserPath, isChromeShell, err := browserPath(options)
		if err != nil {
			return nil, err
		}
		proxyServer, err = newHeadlessProxy(options)
		if err != nil {
			return nil, err
		}
		launcherURL, err = launchBrowser(browserPath, isChromeShell, func(path string) (string, error) {
			chromeLauncher = newChromeLauncher(path)
			return chromeLauncher.Launch()
		})
		if err != nil {
			_ = proxyServer.Close()
			return nil, err
		}
	} else {
		launcherURL = options.CDPEndpoint
	}

	browser := rod.New().ControlURL(launcherURL)
	if browserErr := browser.Connect(); browserErr != nil {
		if proxyServer != nil {
			_ = proxyServer.Close()
		}
		return nil, browserErr
	}
	defaultHeaders := make(map[string]string)
	customAgent := ""
	for _, option := range options.CustomHeaders {
		parts := strings.SplitN(option, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(parts[0], "User-Agent") {
			customAgent = parts[1]
		} else {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k == "" || v == "" {
				continue
			}
			defaultHeaders[k] = v
		}
	}

	engine := &Browser{
		tempDir:        dataStore,
		customAgent:    customAgent,
		defaultHeaders: defaultHeaders,
		engine:         browser,
		options:        options,
		httpClientOnce: &sync.Once{},
		launcher:       chromeLauncher,
		proxy:          proxyServer,
	}
	return engine, nil
}

// browserPath returns the browser binary to launch, empty for the rod default,
// and whether that binary is chrome-headless-shell.
func browserPath(options *types.Options) (string, bool, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return "", false, err
	}

	// if musl is used, most likely we are on alpine linux which is not supported by go-rod, so we fallback to default chrome
	useMusl, _ := fileutil.UseMusl(executablePath)
	if options.UseInstalledChrome || useMusl {
		if chromePath, hasChrome := launcher.LookPath(); hasChrome {
			return chromePath, false, nil
		}
		return "", false, errors.New("the chrome browser is not installed")
	}
	if options.ShowBrowser || !chromeshell.Supported() {
		return "", false, nil
	}

	// Prefer chrome-headless-shell for local headless templates; skip it when
	// headed since the shell binary cannot show a UI.
	ctx, cancel := context.WithTimeout(context.Background(), chromeshell.DefaultDownloadTimeout)
	defer cancel()
	shellPath, err := chromeshell.EnsureWithOptions(ctx, chromeshell.Options{Proxy: downloadProxy(options)})
	if err != nil {
		gologger.Warning().Msgf("Could not prepare chrome-headless-shell, using the default browser: %s\n", err)
		return "", false, nil
	}
	return shellPath, true, nil
}

// downloadProxy returns the scan proxy for the chrome-headless-shell download,
// or empty to use the environment proxy.
func downloadProxy(options *types.Options) string {
	if options.AliveHttpProxy != "" {
		return options.AliveHttpProxy
	}
	return options.AliveSocksProxy
}

// launchBrowser launches browserPath and, only when it is chrome-headless-shell,
// retries once with the default browser. An installed Chrome that fails to
// launch is returned as an error, as before.
func launchBrowser(browserPath string, isChromeShell bool, launch func(string) (string, error)) (string, error) {
	launcherURL, err := launch(browserPath)
	if err == nil || !isChromeShell {
		return launcherURL, err
	}

	gologger.Warning().Msgf("Could not launch chrome-headless-shell, using the default browser: %s\n", err)
	return launch("")
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

// applyDefaultHeaders setsheaders passed via cli -H flag
func (b *Browser) applyDefaultHeaders(p *rod.Page) error {
	pairs := make([]string, 0, len(b.defaultHeaders)*2+2)

	hasAcceptLanguage := false
	for k := range b.defaultHeaders {
		if strings.EqualFold(k, "Accept-Language") {
			hasAcceptLanguage = true
			break
		}
	}
	if !hasAcceptLanguage {
		pairs = append(pairs, "Accept-Language", "en, en-GB, en-us;")
	}
	for k, v := range b.defaultHeaders {
		pairs = append(pairs, k, v)
	}
	if len(pairs) == 0 {
		return nil
	}
	_, err := p.SetExtraHeaders(pairs)
	return err
}

func (b *Browser) getHTTPClient() (*http.Client, error) {
	var err error
	b.httpClientOnce.Do(func() {
		b.httpClient, err = newHttpClient(b.options)
	})
	return b.httpClient, err
}

// Close closes the browser engine
//
// When connected over CDP, it does NOT close the browsers.
func (b *Browser) Close() {
	if b.proxy != nil {
		_ = b.proxy.Close()
	}
	if b.options.CDPEndpoint != "" {
		return
	}

	_ = b.engine.Close()
	b.launcher.Kill()
	_ = os.RemoveAll(b.tempDir)
}
