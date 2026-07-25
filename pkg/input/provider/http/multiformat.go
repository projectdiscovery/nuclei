package http

import (
	"bytes"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr/asn"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/burp"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/json"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/openapi"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/swagger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/yaml"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	urlutil "github.com/projectdiscovery/utils/url"
)

// HttpMultiFormatOptions contains options for the http input provider
type HttpMultiFormatOptions struct {
	// Options for the http input provider
	Options formats.InputFormatOptions
	// InputFile is the file containing the input
	InputFile string
	// InputMode is the mode of input
	InputMode string

	// optional input reader
	InputContents string

	// ExcludeTargets contains URL, host, IP, CIDR, or ASN exclusions to
	// apply to URL target records. Request/response input formats retain their
	// existing protocol-level exclusion behavior.
	ExcludeTargets []string
}

const targetInputProviderType = "TargetInputProvider"

// HttpInputProvider implements an input provider for nuclei that loads
// inputs from multiple formats like burp, openapi, postman,proxify, etc.
type HttpInputProvider struct {
	format       formats.Format
	inputData    []byte
	inputFile    string
	count        int64
	inputType    string
	targetInputs []*contextargs.MetaInput
}

// NewHttpInputProvider creates a new input provider for nuclei from a file
// or an input string
//
// The first preference is given to input file if provided
// otherwise it will use the input string
func NewHttpInputProvider(opts *HttpMultiFormatOptions) (*HttpInputProvider, error) {
	var format formats.Format
	for _, provider := range providersList {
		if provider.Name() == opts.InputMode {
			format = provider
		}
	}
	if format == nil {
		return nil, errors.Errorf("invalid input mode %s", opts.InputMode)
	}
	format.SetOptions(opts.Options)
	// Do a first pass over the input to identify any errors
	// and get the count of the input file as well
	count := int64(0)
	var inputFile *os.File
	var inputReader io.Reader
	if opts.InputFile != "" {
		file, err := os.Open(opts.InputFile)
		if err != nil {
			return nil, errors.Wrap(err, "could not open input file")
		}
		inputFile = file
		inputReader = file
	} else {
		inputReader = strings.NewReader(opts.InputContents)
	}
	defer func() {
		if inputFile != nil {
			_ = inputFile.Close()
		}
	}()

	data, err := io.ReadAll(inputReader)
	if err != nil {
		return nil, errors.Wrap(err, "could not read input file")
	}
	if len(data) == 0 {
		return nil, errors.New("input file is empty")
	}

	var exclusionPolicy *networkpolicy.NetworkPolicy
	var exclusionPolicyErr error
	exclusionPolicyPrepared := false
	targetInputs := make([]*contextargs.MetaInput, 0)
	hasTargetRecords := false
	excludedCount := int64(0)
	parseErr := parseFormat(format, bytes.NewReader(data), opts.InputFile, func(metaInput *contextargs.MetaInput) bool {
		if metaInput == nil {
			return true
		}
		if metaInput.TargetFilter != nil {
			hasTargetRecords = true
			if !exclusionPolicyPrepared {
				exclusionPolicy, exclusionPolicyErr = newTargetExclusionPolicy(opts.ExcludeTargets)
				exclusionPolicyPrepared = true
				if exclusionPolicyErr != nil {
					return false
				}
			}
			if targetIsExcluded(metaInput.Input, exclusionPolicy) {
				excludedCount++
				return true
			}
			targetInputs = append(targetInputs, metaInput)
		}
		count++
		return true
	})
	if exclusionPolicyErr != nil {
		return nil, errors.Wrap(exclusionPolicyErr, "could not prepare target exclusions")
	}
	if parseErr != nil {
		return nil, errors.Wrap(parseErr, "could not parse input file")
	}
	if excludedCount > 0 {
		gologger.Info().Msgf("Number of JSONL targets excluded from input: %d", excludedCount)
	}
	inputType := providerInputType(format, hasTargetRecords)
	if inputType == targetInputProviderType {
		// Target records are cached as parsed MetaInputs, so retaining the raw
		// file would duplicate memory for large JSONL target sets.
		data = nil
	}
	return &HttpInputProvider{
		format:       format,
		inputData:    data,
		inputFile:    opts.InputFile,
		count:        count,
		inputType:    inputType,
		targetInputs: targetInputs,
	}, nil
}

// Count returns the number of items for input provider
func (i *HttpInputProvider) Count() int64 {
	return i.count
}

// Iterate over all inputs in order
func (i *HttpInputProvider) Iterate(callback func(value *contextargs.MetaInput) bool) {
	if i.inputType == targetInputProviderType {
		for _, input := range i.targetInputs {
			if !callback(input.Clone()) {
				return
			}
		}
		return
	}

	err := parseFormat(i.format, bytes.NewReader(i.inputData), i.inputFile, callback)
	if err != nil {
		gologger.Warning().Msgf("Could not parse input file while iterating: %s\n", err)
	}
}

// Set adds item to input provider
// No-op for this provider
func (i *HttpInputProvider) Set(_ string, value string) {}

// SetWithProbe adds item to input provider with http probing
// No-op for this provider
func (i *HttpInputProvider) SetWithProbe(_ string, value string, probe types.InputLivenessProbe) error {
	return nil
}

// SetWithExclusions adds item to input provider if it doesn't match any of the exclusions
// No-op for this provider
func (i *HttpInputProvider) SetWithExclusions(_ string, value string) error {
	return nil
}

// InputType returns the type of input provider
func (i *HttpInputProvider) InputType() string {
	return i.inputType
}

// TargetInputs returns the cached target records for inheritance preparation.
// The returned inputs are owned by the provider and must only be mutated before
// scan execution starts.
func (i *HttpInputProvider) TargetInputs() []*contextargs.MetaInput {
	return i.targetInputs
}

// Close closes the input provider and cleans up any resources
// No-op for this provider
func (i *HttpInputProvider) Close() {}

// Supported Providers
var providersList = []formats.Format{
	burp.New(),
	json.New(),
	yaml.New(),
	openapi.New(),
	swagger.New(),
}

// SupportedFormats returns the list of supported formats in comma-separated
// manner
func SupportedFormats() string {
	var formats []string
	for _, provider := range providersList {
		formats = append(formats, provider.Name())
	}
	return strings.Join(formats, ", ")
}

func parseFormat(format formats.Format, input io.Reader, filePath string, callback formats.ParseMetaInputCallback) error {
	if metaFormat, ok := format.(formats.MetaInputFormat); ok {
		return metaFormat.ParseMeta(input, callback, filePath)
	}
	return format.Parse(input, func(request *types.RequestResponse) bool {
		metaInput := contextargs.NewMetaInput()
		metaInput.ReqResp = request
		metaInput.Input = request.URL.String()
		return callback(metaInput)
	}, filePath)
}

func providerInputType(format formats.Format, hasTargetRecords bool) string {
	if _, ok := format.(formats.MetaInputFormat); ok && hasTargetRecords {
		return targetInputProviderType
	}
	return "MultiFormatInputProvider"
}

func newTargetExclusionPolicy(excludeTargets []string) (*networkpolicy.NetworkPolicy, error) {
	if len(excludeTargets) == 0 {
		return nil, nil
	}

	denyList := make([]string, 0, len(excludeTargets))
	for _, target := range excludeTargets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if asn.IsASN(target) {
			cidrs, err := asn.GetCIDRsForASNNum(target)
			if err != nil {
				return nil, errors.Wrapf(err, "could not resolve excluded ASN %s", target)
			}
			for _, cidr := range cidrs {
				denyList = append(denyList, cidr.String())
			}
			continue
		}
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			parsed, err := urlutil.Parse(target)
			if err == nil && parsed.Host != "" {
				// URL exclusions apply to the target host, matching the list
				// provider's behavior without accidentally matching a query
				// string or path.
				target = "^" + regexp.QuoteMeta(parsed.Host) + "$"
			}
		}
		denyList = append(denyList, target)
	}
	if len(denyList) == 0 {
		return nil, nil
	}
	return networkpolicy.New(networkpolicy.Options{DenyList: denyList})
}

func targetIsExcluded(target string, policy *networkpolicy.NetworkPolicy) bool {
	if policy == nil {
		return false
	}
	parsed, err := urlutil.Parse(target)
	if err != nil || parsed.Host == "" {
		return !policy.Validate(target)
	}
	return !policy.Validate(parsed.Host) || !policy.Validate(parsed.Hostname())
}
