// package list implements a hybrid hmap/filekv backed input provider
// for nuclei that can either stream or store results using different kv stores.
package list

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/filekv"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/mapcidr/asn"
	providerTypes "github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/uncover"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/expand"
	uncoverlib "github.com/projectdiscovery/uncover"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
	readerutil "github.com/projectdiscovery/utils/reader"
	sliceutil "github.com/projectdiscovery/utils/slice"
	urlutil "github.com/projectdiscovery/utils/url"
)

const DefaultMaxDedupeItemsCount = 10000

// ListInputProvider is a hmap/filekv backed nuclei ListInputProvider provider
// it supports list type of input ex: urls,file,stdin,uncover,etc. (i.e just url not complete request/response)
type ListInputProvider struct {
	ipOptions         *ipOptions
	inputCount        int64
	excludedCount     int64
	dupeCount         int64
	skippedCount      int64
	hostMap           *hybrid.HybridMap
	excludedHosts     map[string]struct{}
	hostMapStream     *filekv.FileDB
	hostMapStreamOnce sync.Once
	sync.Once
}

// Options is a wrapper around types.Options structure
type Options struct {
	// Options contains options for hmap provider
	Options *types.Options
	// NotFoundCallback is called for each not found target
	// This overrides error handling for not found target
	NotFoundCallback func(template string) bool
}

// New creates a new hmap backed nuclei Input Provider
// and initializes it based on the passed options Model.
func New(opts *Options) (*ListInputProvider, error) {
	options := opts.Options

	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary input file")
	}

	input := &ListInputProvider{
		hostMap: hm,
		ipOptions: &ipOptions{
			ScanAllIPs: options.ScanAllIPs,
			IPV4:       sliceutil.Contains(options.IPVersion, "4"),
			IPV6:       sliceutil.Contains(options.IPVersion, "6"),
		},
		excludedHosts: make(map[string]struct{}),
	}
	if options.Stream {
		fkvOptions := filekv.DefaultOptions
		fkvOptions.MaxItems = DefaultMaxDedupeItemsCount
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
	if initErr := input.initializeInputSources(opts); initErr != nil {
		return nil, initErr
	}
	if input.excludedCount > 0 {
		gologger.Info().Msgf("Number of hosts excluded from input: %d", input.excludedCount)
	}
	if input.dupeCount > 0 {
		gologger.Info().Msgf("Supplied input was automatically deduplicated (%d removed).", input.dupeCount)
	}
	if input.skippedCount > 0 {
		gologger.Info().Msgf("Number of hosts skipped from input due to exclusion: %d", input.skippedCount)
	}
	return input, nil
}

// Count returns the input count
func (i *ListInputProvider) Count() int64 {
	return i.inputCount
}

// Iterate over all inputs in order
func (i *ListInputProvider) Iterate(callback func(value *contextargs.MetaInput) bool) {
	if i.hostMapStream != nil {
		i.hostMapStreamOnce.Do(func() {
			if err := i.hostMapStream.Process(); err != nil {
				gologger.Warning().Msgf("error in stream mode processing: %s\n", err)
			}
		})
	}
	callbackFunc := func(k, _ []byte) error {
		metaInput := contextargs.NewMetaInput()
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

// Set normalizes and stores passed input values
func (i *ListInputProvider) Set(value string) {
	URL := strings.TrimSpace(value)
	if URL == "" {
		return
	}
	// parse hostname if url is given
	urlx, err := urlutil.Parse(URL)
	if err != nil || (urlx != nil && urlx.Host == "") {
		gologger.Debug().Label("url").MsgFunc(func() string {
			if err != nil {
				return fmt.Sprintf("failed to parse url %v got %v skipping ip selection", URL, err)
			}
			return fmt.Sprintf("got empty hostname for %v skipping ip selection", URL)
		})
		metaInput := contextargs.NewMetaInput()
		metaInput.Input = URL
		i.setItem(metaInput)
		return
	}

	// Check if input is ip or hostname
	if iputil.IsIP(urlx.Hostname()) {
		metaInput := contextargs.NewMetaInput()
		metaInput.Input = URL
		i.setItem(metaInput)
		return
	}

	if i.ipOptions.ScanAllIPs {
		// scan all ips
		dnsData, err := protocolstate.Dialer.GetDNSData(urlx.Hostname())
		if err == nil {
			if (len(dnsData.A) + len(dnsData.AAAA)) > 0 {
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
					metaInput := contextargs.NewMetaInput()
					metaInput.Input = URL
					metaInput.CustomIP = ip
					i.setItem(metaInput)
				}
				return
			} else {
				gologger.Debug().Msgf("scanAllIps: no ip's found reverting to default")
			}
		} else {
			// failed to scanallips falling back to defaults
			gologger.Debug().Msgf("scanAllIps: dns resolution failed: %v", err)
		}
	}

	ips := []string{}
	// only scan the target but ipv6 if it has one
	if i.ipOptions.IPV6 {
		dnsData, err := protocolstate.Dialer.GetDNSData(urlx.Hostname())
		if err == nil && len(dnsData.AAAA) > 0 {
			// pick/ prefer 1st
			ips = append(ips, dnsData.AAAA[0])
		} else {
			gologger.Warning().Msgf("target does not have ipv6 address falling back to ipv4 %v\n", err)
		}
	}
	if i.ipOptions.IPV4 {
		// if IPV4 is enabled do not specify ip let dialer handle it
		ips = append(ips, "")
	}

	for _, ip := range ips {
		metaInput := contextargs.NewMetaInput()
		if ip != "" {
			metaInput.Input = URL
			metaInput.CustomIP = ip
			i.setItem(metaInput)
		} else {
			metaInput.Input = URL
			i.setItem(metaInput)
		}
	}
}

// SetWithProbe only sets the input if it is live
func (i *ListInputProvider) SetWithProbe(value string, probe providerTypes.InputLivenessProbe) error {
	probedValue, err := probe.ProbeURL(value)
	if err != nil {
		return err
	}
	i.Set(probedValue)
	return nil
}

// SetWithExclusions normalizes and stores passed input values if not excluded
func (i *ListInputProvider) SetWithExclusions(value string) error {
	URL := strings.TrimSpace(value)
	if URL == "" {
		return nil
	}
	if i.isExcluded(URL) {
		i.skippedCount++
		return nil
	}
	i.Set(URL)
	return nil
}

// ListInputProvider is a hmap/filekv backed nuclei ListInputProvider provider
func (i *ListInputProvider) InputType() string {
	return "ListInputProvider"
}

// Close closes the input provider
func (i *ListInputProvider) Close() {
	i.hostMap.Close()
	if i.hostMapStream != nil {
		i.hostMapStream.Close()
	}
}

// initializeInputSources initializes the input sources for hmap input
func (i *ListInputProvider) initializeInputSources(opts *Options) error {
	options := opts.Options

	// Handle targets flags
	for _, target := range options.Targets {
		switch {
		case iputil.IsCIDR(target):
			ips := expand.CIDR(target)
			i.addTargets(ips)
		case asn.IsASN(target):
			ips := expand.ASN(target)
			i.addTargets(ips)
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
			// Handle cloud based input here.
			if opts.NotFoundCallback == nil || !opts.NotFoundCallback(options.TargetsFilePath) {
				return errors.Wrap(inputErr, "could not open targets file")
			}
		}
		if input != nil {
			i.scanInputFromReader(input)
			input.Close()
		}
	}
	if options.Uncover && options.UncoverQuery != nil {
		gologger.Info().Msgf("Running uncover query against: %s", strings.Join(options.UncoverEngine, ","))
		uncoverOpts := &uncoverlib.Options{
			Agents:        options.UncoverEngine,
			Queries:       options.UncoverQuery,
			Limit:         options.UncoverLimit,
			MaxRetry:      options.Retries,
			Timeout:       options.Timeout,
			RateLimit:     uint(options.UncoverRateLimit),
			RateLimitUnit: time.Minute, // default unit is minute
		}
		ch, err := uncover.GetTargetsFromUncover(context.TODO(), options.UncoverField, uncoverOpts)
		if err != nil {
			return err
		}
		for c := range ch {
			i.Set(c)
		}
	}

	if len(options.ExcludeTargets) > 0 {
		for _, target := range options.ExcludeTargets {
			switch {
			case iputil.IsCIDR(target):
				ips := expand.CIDR(target)
				i.removeTargets(ips)
			case asn.IsASN(target):
				ips := expand.ASN(target)
				i.removeTargets(ips)
			default:
				i.Del(target)
			}
		}
	}

	return nil
}

// scanInputFromReader scans a line of input from reader and passes it for storage
func (i *ListInputProvider) scanInputFromReader(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		item := scanner.Text()
		switch {
		case iputil.IsCIDR(item):
			ips := expand.CIDR(item)
			i.addTargets(ips)
		case asn.IsASN(item):
			ips := expand.ASN(item)
			i.addTargets(ips)
		default:
			i.Set(item)
		}
	}
}

// isExcluded checks if a URL is in the exclusion list
func (i *ListInputProvider) isExcluded(URL string) bool {
	metaInput := contextargs.NewMetaInput()
	metaInput.Input = URL
	key, err := metaInput.MarshalString()
	if err != nil {
		gologger.Warning().Msgf("%s\n", err)
		return false
	}

	_, exists := i.excludedHosts[key]
	return exists
}

func (i *ListInputProvider) Del(value string) {
	URL := strings.TrimSpace(value)
	if URL == "" {
		return
	}
	// parse hostname if url is given
	urlx, err := urlutil.Parse(URL)
	if err != nil || (urlx != nil && urlx.Host == "") {
		gologger.Debug().Label("url").MsgFunc(func() string {
			if err != nil {
				return fmt.Sprintf("failed to parse url %v got %v skipping ip selection", URL, err)
			}
			return fmt.Sprintf("got empty hostname for %v skipping ip selection", URL)
		})
		metaInput := contextargs.NewMetaInput()
		metaInput.Input = URL
		i.delItem(metaInput)
		return
	}

	// Check if input is ip or hostname
	if iputil.IsIP(urlx.Hostname()) {
		metaInput := contextargs.NewMetaInput()
		metaInput.Input = URL
		i.delItem(metaInput)
		return
	}

	if i.ipOptions.ScanAllIPs {
		// scan all ips
		dnsData, err := protocolstate.Dialer.GetDNSData(urlx.Hostname())
		if err == nil {
			if (len(dnsData.A) + len(dnsData.AAAA)) > 0 {
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
					metaInput := contextargs.NewMetaInput()
					metaInput.Input = value
					metaInput.CustomIP = ip
					i.delItem(metaInput)
				}
				return
			} else {
				gologger.Debug().Msgf("scanAllIps: no ip's found reverting to default")
			}
		} else {
			// failed to scanallips falling back to defaults
			gologger.Debug().Msgf("scanAllIps: dns resolution failed: %v", err)
		}
	}

	ips := []string{}
	// only scan the target but ipv6 if it has one
	if i.ipOptions.IPV6 {
		dnsData, err := protocolstate.Dialer.GetDNSData(urlx.Hostname())
		if err == nil && len(dnsData.AAAA) > 0 {
			// pick/ prefer 1st
			ips = append(ips, dnsData.AAAA[0])
		} else {
			gologger.Warning().Msgf("target does not have ipv6 address falling back to ipv4 %v\n", err)
		}
	}
	if i.ipOptions.IPV4 {
		// if IPV4 is enabled do not specify ip let dialer handle it
		ips = append(ips, "")
	}

	for _, ip := range ips {
		metaInput := contextargs.NewMetaInput()
		if ip != "" {
			metaInput.Input = URL
			metaInput.CustomIP = ip
			i.delItem(metaInput)
		} else {
			metaInput.Input = URL
			i.delItem(metaInput)
		}
	}
}

// setItem in the kv store
func (i *ListInputProvider) setItem(metaInput *contextargs.MetaInput) {
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
		i.setHostMapStream(key)
	}
}

// setItem in the kv store
func (i *ListInputProvider) delItem(metaInput *contextargs.MetaInput) {
	targetUrl, err := urlutil.ParseURL(metaInput.Input, true)
	if err != nil {
		gologger.Warning().Msgf("%s\n", err)
		return
	}

	i.hostMap.Scan(func(k, _ []byte) error {
		var tmpMetaInput contextargs.MetaInput
		if err := tmpMetaInput.Unmarshal(string(k)); err != nil {
			return err
		}
		tmpKey, err := tmpMetaInput.MarshalString()
		if err != nil {
			return err
		}
		tmpUrl, err := urlutil.ParseURL(tmpMetaInput.Input, true)
		if err != nil {
			return err
		}

		matched, _ := regexp.MatchString(metaInput.Input, tmpUrl.Host)
		if tmpUrl.Host == targetUrl.Host || matched {
			_ = i.hostMap.Del(tmpKey)
			i.excludedHosts[tmpKey] = struct{}{}
			i.excludedCount++
			i.inputCount--
		}
		return nil
	})
}

// setHostMapStream sets item in stream mode
func (i *ListInputProvider) setHostMapStream(data string) {
	if _, err := i.hostMapStream.Merge([][]byte{[]byte(data)}); err != nil {
		gologger.Warning().Msgf("%s\n", err)
		return
	}
}

func (i *ListInputProvider) addTargets(targets []string) {
	for _, target := range targets {
		i.Set(target)
	}
}

func (i *ListInputProvider) removeTargets(targets []string) {
	for _, target := range targets {
		metaInput := contextargs.NewMetaInput()
		metaInput.Input = target
		i.delItem(metaInput)
	}
}
