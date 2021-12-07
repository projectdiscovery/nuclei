package runner

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

var proxyURLList []url.URL

// loadProxyServers load list of proxy servers from file or comma seperated
func loadProxyServers(options *types.Options) error {
	if len(options.Proxy) == 0 {
		return nil
	}
	for _, p := range options.Proxy {
		if proxyURL, err := validateProxyURL(p); err == nil {
			proxyURLList = append(proxyURLList, proxyURL)
		} else if fileutil.FileExists(p) {
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
				if proxyURL, err := validateProxyURL(proxy); err != nil {
					return err
				} else {
					proxyURLList = append(proxyURLList, proxyURL)
				}
			}
		} else {
			return fmt.Errorf("invalid proxy file or URL provided for %s", p)
		}
	}
	return processProxyList(options)
}

func processProxyList(options *types.Options) error {
	if len(proxyURLList) == 0 {
		return fmt.Errorf("could not find any valid proxy")
	} else {
		done := make(chan bool)
		exitCounter := make(chan bool)
		counter := 0
		for _, url := range proxyURLList {
			go runProxyConnectivity(url, options, done, exitCounter)
		}
		for {
			select {
			case <-done:
				{
					close(done)
					return nil
				}
			case <-exitCounter:
				{
					if counter += 1; counter == len(proxyURLList) {
						return errors.New("no reachable proxy found")
					}
				}
			}
		}
	}
}

func runProxyConnectivity(proxyURL url.URL, options *types.Options, done chan bool, exitCounter chan bool) {
	if err := testProxyConnection(proxyURL, options.Timeout); err == nil {
		if types.ProxyURL == "" && types.ProxySocksURL == "" {
			assignProxyURL(proxyURL, options)
			done <- true
		}
	}
	exitCounter <- true
}

func testProxyConnection(proxyURL url.URL, timeoutDelay int) error {
	timeout := time.Duration(timeoutDelay) * time.Second
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", proxyURL.Hostname(), proxyURL.Port()), timeout)
	if err != nil {
		return err
	}
	return nil
}

func assignProxyURL(proxyURL url.URL, options *types.Options) {
	os.Setenv(types.HTTP_PROXY_ENV, proxyURL.String())
	if proxyURL.Scheme == types.HTTP || proxyURL.Scheme == types.HTTPS {
		types.ProxyURL = proxyURL.String()
		types.ProxySocksURL = ""
		gologger.Verbose().Msgf("Using %s as proxy server", proxyURL.String())
	} else if proxyURL.Scheme == types.SOCKS5 {
		types.ProxyURL = ""
		types.ProxySocksURL = proxyURL.String()
		gologger.Verbose().Msgf("Using %s as socket proxy server", proxyURL.String())
	}
}

func validateProxyURL(proxy string) (url.URL, error) {
	if url, err := url.Parse(proxy); err == nil && isSupportedProtocol(url.Scheme) {
		return *url, nil
	}
	return url.URL{}, errors.New("invalid proxy format (It should be http[s]/socks5://[username:password@]host:port)")
}

// isSupportedProtocol checks given protocols are supported
func isSupportedProtocol(value string) bool {
	return value == types.HTTP || value == types.HTTPS || value == types.SOCKS5
}
