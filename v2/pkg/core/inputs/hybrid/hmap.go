// Package hybrid implements a hybrid hmap/filekv backed input provider
// for nuclei that can either stream or store results using different kv stores.
package hybrid

import (
	"bufio"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/filekv"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/stringsutil"
)

// Input is a hmap/filekv backed nuclei Input provider
type Input struct {
	ipOptions     *ipOptions
	inputCount    int64
	dupeCount     int64
	hostMap       *hybrid.HybridMap
	hostMapStream *filekv.FileDB
}

// New creates a new hmap backed nuclei Input Provider
// and initializes it based on the passed options Model.
func New(options *types.Options) (*Input, error) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary input file")
	}

	input := &Input{
		hostMap: hm,
		ipOptions: &ipOptions{
			ScanAllIPs: options.ScanAllIPs,
			IPV4:       stringsutil.ContainsAny(options.IPVersion, "4", "any"),
			IPV6:       stringsutil.ContainsAny(options.IPVersion, "6", "any"),
		},
	}
	if options.Stream {
		fkvOptions := filekv.DefaultOptions
		if tmpFileName, err := fileutil.GetTempFileName(); err != nil {
			return nil, errors.Wrap(err, "could not create temporary input file")
		} else {
			fkvOptions.Path = tmpFileName
		}
		fkv, err := filekv.Open(fkvOptions)
		if err != nil {
			return nil, errors.Wrap(err, "could not create temporary unsorted input file")
		}
		input.hostMapStream = fkv
	}
	if initErr := input.initializeInputSources(options); initErr != nil {
		return nil, initErr
	}
	if input.dupeCount > 0 {
		gologger.Info().Msgf("Supplied input was automatically deduplicated (%d removed).", input.dupeCount)
	}
	return input, nil
}

// Close closes the input provider
func (i *Input) Close() {
	i.hostMap.Close()
	if i.hostMapStream != nil {
		i.hostMapStream.Close()
	}
}

// initializeInputSources initializes the input sources for hmap input
func (i *Input) initializeInputSources(options *types.Options) error {
	// Handle targets flags
	for _, target := range options.Targets {
		if iputil.IsCIDR(target) {
			i.expandCIDRInputValue(target)
			continue
		}
		i.normalizeStoreInputValue(target)
	}

	// Handle stdin
	if options.Stdin {
		i.scanInputFromReader(fileutil.TimeoutReader{Reader: os.Stdin, Timeout: time.Duration(options.InputReadTimeout)})
	}

	// Handle target file
	if options.TargetsFilePath != "" {
		input, inputErr := os.Open(options.TargetsFilePath)
		if inputErr != nil {
			return errors.Wrap(inputErr, "could not open targets file")
		}
		i.scanInputFromReader(input)
		input.Close()
	}
	return nil
}

// scanInputFromReader scans a line of input from reader and passes it for storage
func (i *Input) scanInputFromReader(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		if iputil.IsCIDR(scanner.Text()) {
			i.expandCIDRInputValue(scanner.Text())
			continue
		}
		i.normalizeStoreInputValue(scanner.Text())
	}
}

// normalizeStoreInputValue normalizes and stores passed input values
func (i *Input) normalizeStoreInputValue(value string) {
	URL := strings.TrimSpace(value)
	if URL == "" {
		return
	}

	if _, ok := i.hostMap.Get(URL); ok {
		i.dupeCount++
		return
	}

	switch {
	case i.ipOptions.ScanAllIPs:
		// we need to resolve the hostname
		// check if it's an url
		var host string
		parsedURL, err := url.Parse(value)
		if err == nil && parsedURL.Host != "" {
			host = parsedURL.Host
		} else {
			parsedURL = nil
			host = value
		}

		if dnsData, err := protocolstate.Dialer.GetDNSData(host); err == nil {
			var ips []string
			if i.ipOptions.IPV4 {
				ips = append(ips, dnsData.A...)
			}
			if i.ipOptions.IPV6 {
				ips = append(ips, dnsData.AAAA...)
			}

			for _, ip := range ips {
				i.inputCount++
				var newHost string
				if iputil.IsIPv4(ip) {
					newHost = ip
					if parsedURL != nil {
						parsedURL.Host = ip
					}
				} else if iputil.IsIPv6(ip) {
					newHost = ip
					if parsedURL != nil {
						parsedURL.Host = "[" + ip + "]"
					}
				}

				var finalHost string
				if parsedURL != nil {
					finalHost = parsedURL.String()
					if !stringsutil.HasPrefixAny(value, "http://", "https://") {
						finalHost = stringsutil.TrimPrefixAny(value, "http://", "https://")
					}
				} else {
					finalHost = newHost
				}

				_ = i.hostMap.Set(finalHost, nil)
				if i.hostMapStream != nil {
					_ = i.hostMapStream.Set([]byte(finalHost), nil)
				}
			}
			break
		}
		// in case we have an error just fallthrough
		fallthrough
	default:
		i.inputCount++
		_ = i.hostMap.Set(URL, nil)
		if i.hostMapStream != nil {
			_ = i.hostMapStream.Set([]byte(URL), nil)
		}
	}
}

// Count returns the input count
func (i *Input) Count() int64 {
	return i.inputCount
}

// Scan iterates the input and each found item is passed to the
// callback consumer.
func (i *Input) Scan(callback func(value string)) {
	callbackFunc := func(k, _ []byte) error {
		callback(string(k))
		return nil
	}
	if i.hostMapStream != nil {
		_ = i.hostMapStream.Scan(callbackFunc)
	} else {
		i.hostMap.Scan(callbackFunc)
	}
}

// expandCIDRInputValue expands CIDR and stores expanded IPs
func (i *Input) expandCIDRInputValue(value string) {
	ips, _ := mapcidr.IPAddressesAsStream(value)
	for ip := range ips {
		if _, ok := i.hostMap.Get(ip); ok {
			i.dupeCount++
			continue
		}
		i.inputCount++
		_ = i.hostMap.Set(ip, nil)
		if i.hostMapStream != nil {
			_ = i.hostMapStream.Set([]byte(ip), nil)
		}
	}
}
