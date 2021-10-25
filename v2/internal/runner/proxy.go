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
	if options.Proxy == "" {
		return nil
	}
	if fileutil.FileExists(options.Proxy) {
		file, err := os.Open(options.Proxy)
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
			if err := validateProxy(proxy); err != nil {
				return fmt.Errorf("%s", err)
			}
			options.ProxyURLList = append(options.ProxyURLList, proxy)
		}
	} else {
		for _, proxy := range strings.Split(options.Proxy, ",") {
			if strings.TrimSpace(proxy) == "" {
				continue
			}
			if err := validateProxy(proxy); err != nil {
				return err
			}
			options.ProxyURLList = append(options.ProxyURLList, proxy)
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
		for _, ip := range options.ProxyURLList {
			go runProxyConnectivity(ip, options, done, exitCounter)
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

func runProxyConnectivity(ip string, options *types.Options, done chan bool, exitCounter chan bool) {
	if proxy, err := testProxyConnection(ip, options.Timeout); err == nil {
		if options.ProxyURL == "" && options.ProxySocksURL == "" {
			if valid := assignProxy(proxy, options); valid {
				done <- true
			}
		}
	}
	exitCounter <- true
}

func testProxyConnection(proxy string, timeoutDelay int) (string, error) {
	ip, _ := url.Parse(proxy)
	timeout := time.Duration(timeoutDelay) * time.Second
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", ip.Hostname(), ip.Port()), timeout)
	if err != nil {
		return "", err
	}
	return proxy, nil
}

func assignProxy(proxy string, options *types.Options) bool {
	var validConfig bool = true
	if strings.HasPrefix(proxy, "http") || strings.HasPrefix(proxy, "https") {
		options.ProxyURL = proxy
		options.ProxySocksURL = ""
		gologger.Verbose().Msgf("Using %s as proxy server", options.ProxyURL)
	} else if strings.HasPrefix(proxy, "socks5") || strings.HasPrefix(proxy, "socks4") {
		options.ProxyURL = ""
		options.ProxySocksURL = proxy
		gologger.Verbose().Msgf("Using %s as socket proxy server", options.ProxySocksURL)
	} else {
		validConfig = false
	}
	return validConfig

}

func validateProxy(proxy string) error {
	if proxy != "" && !isValidURL(proxy) && isSupportedProtocol(proxy) {
		return errors.New("invalid proxy format (It should be http/socks5://[username:password]@host:port)")
	}
	return nil
}

//isSupportedProtocol checks given protocols are supported
func isSupportedProtocol(proxy string) bool {
	return strings.HasPrefix(proxy, "https") || strings.HasPrefix(proxy, "http") || strings.HasPrefix(proxy, "socks5") || strings.HasPrefix(proxy, "socks4")
}

//isValidURL checks for valid url
func isValidURL(urlString string) bool {
	_, err := url.Parse(urlString)
	return err == nil
}
