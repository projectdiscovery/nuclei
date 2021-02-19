package engine

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Browser is a browser structure for nuclei headless module
type Browser struct {
	customAgent string
	engine      *rod.Browser
	httpclient  *http.Client
	options     *types.Options
}

// New creates a new katana headless browser module
func New(options *types.Options) (*Browser, error) {
	launcher := launcher.New().
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
		Headless(false).
		Delete("use-mock-keychain")

	if options.ProxyURL != "" {
		launcher = launcher.Proxy(options.ProxyURL)
	}
	launcherURL, err := launcher.Launch()
	if err != nil {
		return nil, err
	}

	browser := rod.New().ControlURL(launcherURL)
	if err := browser.Connect(); err != nil {
		return nil, err
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
	httpclient, err := newhttpClient(options)
	if err != nil {
		return nil, err
	}
	return &Browser{customAgent: customAgent, engine: browser, httpclient: httpclient, options: options}, nil
}
