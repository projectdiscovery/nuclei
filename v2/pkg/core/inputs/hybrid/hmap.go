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
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/mapcidr"
	asn "github.com/projectdiscovery/mapcidr/asn"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/uncover"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
	readerutil "github.com/projectdiscovery/utils/reader"
	sliceutil "github.com/projectdiscovery/utils/slice"
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
			IPV4:       sliceutil.Contains(options.IPVersion, "4"),
			IPV6:       sliceutil.Contains(options.IPVersion, "6"),
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
		switch {
		case iputil.IsCIDR(target):
			i.expandCIDRInputValue(target)
		case asn.IsASN(target):
			i.expandASNInputValue(target)
		default:
			i.Set(target)
		}
	}

	// Handle stdin
	if options.Stdin {
		i.scanInputFromReader(readerutil.TimeoutReader{Reader: os.Stdin, Timeout: time.Duration(options.InputReadTimeout)})
	}

	// Handle target file
	if options.TargetsFilePath != "" {
		input, inputErr := os.Open(options.TargetsFilePath)
		if inputErr != nil {
			return errors.Wrap(inputErr, "could not open targets file")
		}
		defer input.Close()

		i.scanInputFromReader(input)
	}
	if options.Uncover && options.UncoverQuery != nil {
		gologger.Info().Msgf("Running uncover query against: %s", strings.Join(options.UncoverEngine, ","))
		ch, err := uncover.GetTargetsFromUncover(options.UncoverDelay, options.UncoverLimit, options.UncoverField, options.UncoverEngine, options.UncoverQuery)
		if err != nil {
			return err
		}
		for c := range ch {
			i.Set(c)
		}
	}
	return nil
}

// scanInputFromReader scans a line of input from reader and passes it for storage
func (i *Input) scanInputFromReader(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		item := scanner.Text()
		switch {
		case iputil.IsCIDR(item):
			i.expandCIDRInputValue(item)
		case asn.IsASN(item):
			i.expandASNInputValue(item)
		default:
			i.Set(item)
		}
	}
}

// Set normalizes and stores passed input values
func (i *Input) Set(value string) {
	URL := strings.TrimSpace(value)
	if URL == "" {
		return
	}
	// actual hostname
	var host string
	// parse hostname if url is given
	parsedURL, err := url.Parse(value)
	if err == nil && parsedURL.Host != "" {
		host = parsedURL.Host
	} else {
		parsedURL = nil
		host = value
	}

	if i.ipOptions.ScanAllIPs {
		// scan all ips
		dnsData, err := protocolstate.Dialer.GetDNSData(host)
		if err == nil && (len(dnsData.A)+len(dnsData.AAAA)) > 0 {
			var ips []string
			if i.ipOptions.IPV4 {
				ips = append(ips, dnsData.A...)
			}
			if i.ipOptions.IPV6 {
				ips = append(ips, dnsData.AAAA...)
			}
			for _, ip := range ips {
				if ip == "" {
					continue
				}
				metaInput := &contextargs.MetaInput{Input: value, CustomIP: ip}
				i.setItem(metaInput)
			}
			return
		}
		// failed to scanallips falling back to defaults
		gologger.Error().Msgf("failed to scan all ips reverting to default %v", err)
	}

	ips := []string{}
	// only scan the target but ipv6 if it has one
	if i.ipOptions.IPV6 {
		dnsData, err := protocolstate.Dialer.GetDNSData(host)
		if err == nil && len(dnsData.AAAA) > 0 {
			// pick/ prefer 1st
			ips = append(ips, dnsData.AAAA[0])
		} else {
			gologger.Warning().Msgf("target does not have ipv6 address falling back to ipv4 %s\n", err)
		}
	}
	if i.ipOptions.IPV4 {
		// if IPV4 is enabled do not specify ip let dialer handle it
		ips = append(ips, "")
	}

	for _, ip := range ips {
		if ip != "" {
			metaInput := &contextargs.MetaInput{Input: URL, CustomIP: ip}
			i.setItem(metaInput)
		} else {
			metaInput := &contextargs.MetaInput{Input: URL}
			i.setItem(metaInput)
		}
	}

}

// setItem in the kv store
func (i *Input) setItem(metaInput *contextargs.MetaInput) {
	key, err := metaInput.MarshalString()
	if err != nil {
		gologger.Warning().Msgf("%s\n", err)
		return
	}
	if _, ok := i.hostMap.Get(key); ok {
		i.dupeCount++
		return
	}

	i.inputCount++ // tracks target count
	_ = i.hostMap.Set(key, nil)
	if i.hostMapStream != nil {
		_ = i.hostMapStream.Set([]byte(key), nil)
	}
}

// Count returns the input count
func (i *Input) Count() int64 {
	return i.inputCount
}

// Scan iterates the input and each found item is passed to the
// callback consumer.
func (i *Input) Scan(callback func(value *contextargs.MetaInput) bool) {
	callbackFunc := func(k, _ []byte) error {
		metaInput := &contextargs.MetaInput{}
		if err := metaInput.Unmarshal(string(k)); err != nil {
			return err
		}
		if !callback(metaInput) {
			return io.EOF
		}
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
		metaInput := &contextargs.MetaInput{Input: ip}
		key, err := metaInput.MarshalString()
		if err != nil {
			gologger.Warning().Msgf("%s\n", err)
			return
		}
		if _, ok := i.hostMap.Get(key); ok {
			i.dupeCount++
			continue
		}
		i.inputCount++
		_ = i.hostMap.Set(key, nil)
		if i.hostMapStream != nil {
			_ = i.hostMapStream.Set([]byte(key), nil)
		}
	}
}

// expandASNInputValue expands CIDRs for given ASN and stores expanded IPs
func (i *Input) expandASNInputValue(value string) {
	asnClient := asn.New()
	cidrs, _ := asnClient.GetCIDRsForASNNum(value)
	for _, cidr := range cidrs {
		i.expandCIDRInputValue(cidr.String())
	}
}
