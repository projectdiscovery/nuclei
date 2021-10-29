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

// loadProxyServers load list of proxy servers from file or comma seperated
func loadProxyServers(options *types.Options) error {
	if len(options.Proxy) == 0 {
		return nil
	}
	for _, p := range strings.Split(options.Proxy, ",") {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if isSupportedProtocol(p, true) {
			if proxyURL, err := validateProxyURL(p); err != nil {
				return err
			} else {
				options.ProxyURLList = append(options.ProxyURLList, proxyURL)
			}
		} else if fileutil.FileExists(p) {
			file, err := os.Open(p)
			if err != nil {
				return fmt.Errorf("could not open proxy file: %s", err)
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
					options.ProxyURLList = append(options.ProxyURLList, proxyURL)
				}
			}
		} else {
			return errors.New("invalid proxy file or URL provided")
		}
	}
	return processProxyList(options)
}

func processProxyList(options *types.Options) error {
	if len(options.ProxyURLList) == 0 {
		return fmt.Errorf("could not find any valid proxy")
	} else {
		done := make(chan bool)
		exitCounter := make(chan bool)
		counter := 0
		for _, url := range options.ProxyURLList {
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
					if counter += 1; counter == len(options.ProxyURLList) {
						return errors.New("no reachable proxy found")
					}
				}
			}
		}
	}
}

func runProxyConnectivity(proxyURL url.URL, options *types.Options, done chan bool, exitCounter chan bool) {
	if err := testProxyConnection(proxyURL, options.Timeout); err == nil {
		if options.ProxyURL == "" && options.ProxySocksURL == "" {
			if valid := assignProxyURL(proxyURL, options); valid {
				done <- true
			}
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

func assignProxyURL(proxyURL url.URL, options *types.Options) bool {
	var isValid bool = true
	if proxyURL.Scheme == "http" || proxyURL.Scheme == "https" {
		options.ProxyURL = proxyURL.String()
		options.ProxySocksURL = ""
		gologger.Verbose().Msgf("Using %s as proxy server", options.ProxyURL)
	} else if proxyURL.Scheme == "socks5" {
		options.ProxyURL = ""
		options.ProxySocksURL = proxyURL.String()
		gologger.Verbose().Msgf("Using %s as socket proxy server", options.ProxySocksURL)
	} else {
		isValid = false
	}
	return isValid
}

func validateProxyURL(proxy string) (url.URL, error) {
	if url, err := url.Parse(proxy); err == nil && isSupportedProtocol(url.Scheme, false) {
		return *url, nil
	}
	return url.URL{}, errors.New("invalid proxy format (It should be http[s]/socks5://[username:password@]host:port)")
}

//isSupportedProtocol checks given protocols are supported
func isSupportedProtocol(value string, prefixCheck bool) bool {
	if prefixCheck {
		value = strings.ToLower(value)
		return strings.HasPrefix(value, "http") || strings.HasPrefix(value, "https") || strings.HasPrefix(value, "socks5")
	}
	return value == "http" || value == "https" || value == "socks5"
}
