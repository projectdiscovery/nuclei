package runner

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	proxyutils "github.com/projectdiscovery/utils/proxy"
)

// loadProxyServers load list of proxy servers from file or comma separated
func loadProxyServers(options *types.Options) error {
	if len(options.Proxy) == 0 {
		return nil
	}
	proxyList := []string{}
	for _, p := range options.Proxy {
		if fileutil.FileExists(p) {
			file, err := os.Open(p)
			if err != nil {
				return fmt.Errorf("could not open proxy file: %w", err)
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				proxy := scanner.Text()
				if strings.TrimSpace(proxy) == "" {
					continue
				}
				proxyList = append(proxyList, proxy)
			}
		} else {
			proxyList = append(proxyList, p)
		}
	}
	aliveProxy, err := proxyutils.GetAnyAliveProxy(options.Timeout, proxyList...)
	if err != nil {
		return err
	}
	proxyURL, err := url.Parse(aliveProxy)
	if err != nil {
		return errorutil.WrapfWithNil(err, "failed to parse proxy got %v", err)
	}
	if options.ProxyInternal {
		os.Setenv(types.HTTP_PROXY_ENV, proxyURL.String())
	}
	if proxyURL.Scheme == proxyutils.HTTP || proxyURL.Scheme == proxyutils.HTTPS {
		types.ProxyURL = proxyURL.String()
		types.ProxySocksURL = ""
		gologger.Verbose().Msgf("Using %s as proxy server", proxyURL.String())
	} else if proxyURL.Scheme == proxyutils.SOCKS5 {
		types.ProxyURL = ""
		types.ProxySocksURL = proxyURL.String()
		gologger.Verbose().Msgf("Using %s as socket proxy server", proxyURL.String())
	}
	return nil
}
